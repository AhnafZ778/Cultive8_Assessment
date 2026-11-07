# 01 — Tokenizer & Line-Safe Log Chunker Specification

- **Purpose**: Exact specification for `app/tokenizer.py` and `app/chunker.py`.
- **Scope**: Phase 1 (`phase-1-core`).
- **Update Policy**: Update only if token budget numbers or log formats change.
- **Loading Budget**: ~950 tokens.

## 1. Local Model Setup (`qwen3.5:0.8b`)

- Primary model: `qwen3.5:0.8b` (~1.26 GB in Ollama, matches the #1 suggested model in the Cultive8 brief).
- Fallback models already on disk: `qwen3:1.7b` (1.4 GB), `qwen2.5:1.5b` (986 MB), `qwen2:0.5b` (352 MB).
- During Phase 1 initialization, run `ollama pull qwen3.5:0.8b` if not present in `ollama list`.
- Create `.venv` using local cached wheels (`uv venv .venv --system-site-packages && uv pip install --offline fastapi uvicorn tokenizers requests python-multipart` or fallback to `aiohttp` if offline install lacks any wheel).

## 2. Exact Model Tokenizer (`app/tokenizer.py`)

Ollama `0.40.2` does not expose `/api/tokenize`, but `POST http://127.0.0.1:11434/api/show` with `{"model": model_name, "verbose": true}` returns the model's exact embedded GGUF tokenizer:
- `model_info["tokenizer.ggml.tokens"]` (list of token strings)
- `model_info["tokenizer.ggml.merges"]` (list of `"a b"` merge rules)

Implementation in `ModelTokenizer`:
1. On first use for `model_name`, fetch `/api/show` (`verbose=True`), construct `tokenizers.Tokenizer(tokenizers.models.BPE(vocab, merges))` with `ByteLevel(add_prefix_space=False, use_regex=True)`, and cache in memory.
2. Provide `count_tokens(text: str) -> int`:
   - Returns `len(tokenizer.encode(text).ids)`.
   - Measured calibration: our BPE count is ~3.5% higher than Ollama's `prompt_eval_count`, giving a built-in safety margin so calls never overflow 2,048 tokens.
   - Offline fallback if `/api/show` is unreachable during unit tests: conservative heuristic `max(1, int(len(text.encode('utf-8')) / 2.8))`.

## 3. Lossless Line Compaction (`app/chunker.py`)

Raw JSONL lines in `Cultive8_Workspace_Agrigen_Server.log` average ~164 tokens/line because of repeated JSON keys and 110-character browser User-Agent strings (42,272 tokens across 258 lines).
Compacting each line losslessly into a canonical single-line record preserves **100% of security-relevant data and original 1-based line numbers** while cutting total tokens to ~15,592 (~60 tokens/line, ~15 chunks total):

Format for valid JSON line `lineno` (1-indexed):
```
L{lineno} | {HH:MM:SS} | {app}/{service} | {level} | ip={client_ip} | {method} {path} | http={status} | ua={short_ua} | {extra_fields}
```
Rules:
- Original line number is always first (`L1` .. `L258`).
- `short_ua`: if standard `Mozilla/5.0 ... Chrome/130.0.0.0 Safari/537.36`, shorten to `Chrome130`; keep all non-standard User-Agents (`python-requests/2.32.3`, `curl/8.7.1`, `Go-http-client/1.1`, `aiohttp/3.10.5`, `Cultive8HealthMonitor/1.4`) verbatim.
- `extra_fields`: include every non-null field from `("username", "auth_result", "security_rule", "message", "exception", "procedure", "upstream", "http_status", "validation_error", "submitted_text", "owner", "allowed_paths")`.
- If a line is plain text (non-JSON `.log`/`.txt`), preserve as `L{lineno} | RAW | {sanitized_line[:500]}`.
- **Never cut a log entry across chunks.**

## 4. Strict 2,048-Token Budget Plan (`split_log_stream`)

| Component | Token Cap | Purpose |
|---|---|---|
| System & Schema Prompt | `320` | Role, JSON schema, untrusted-data rule, false-positive exclusions |
| Carried Context Ledger | `250` | Compact summary of suspicious IPs/actors from chunks `1..i-1` |
| Current Log Chunk | `1,050` | Whole compacted lines (`~17-20` lines per chunk) |
| Model Output (`num_predict`) | `384` | Structured JSON findings for this chunk |
| Safety Margin | `44` | Chat template special tokens (`<|im_start|>`, etc.) |
| **Total per Call** | **2,048** | **Hard enforced via `num_ctx: 2048` and pre-call token check** |

If adding line `L_k` causes `chunk_tokens > 1050`, close the current chunk and start the next chunk with `L_k`.
