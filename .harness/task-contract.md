# Task contract — Cultive8 local log analyzer

Audience and outcome:
Cultive8 interviewers. A local-AI web app that runs `qwen3.5:0.8b` via Ollama, splits the supplied 258-line JSONL server log inside a hard 2,048-token budget per call, links multi-part attack chains across the file, and renders one unified security report in a "drunk-man usable" operational interface. Deadline 7 Nov 2026, 23:01:53 Asia/Dhaka.

Current source identity:
Folder `/home/ahnaf-zakaria/Desktop/Cultive8` contains `Candidate evaluation _ Cultive8.pdf`, `Cultive8_Workspace_Agrigen_Server.log`, and the complete modular design foundation under `.harness/design/00..05`. No application code has been written yet.

Acceptance examples (observable):
- Upload accepts `.log` or `.txt` (plus a 1-click button for the supplied Cultive8 log). Invalid/binary/empty uploads show an inline alert without crashing.
- The log is compacted losslessly with explicit `L1..L258` prefixes and split only on whole lines. Every call stays `<= 2,048` tokens (Prompt `<=320` + Carried Ledger `<=250` + Log Chunk `<=1,050` + Reserved Output `384` + Margin `44`), counted with the model's exact GGUF BPE tokenizer from Ollama `/api/show` (`verbose=true`) and verified by Ollama `prompt_eval_count` + `eval_count`.
- Calls run sequentially (1 at a time) against `qwen3.5:0.8b` with `"think": false` and `"format": "json"`. Partial state persists to `runs/<job_id>/state.json` after each chunk.
- Related events across chunks are merged into one unified report (`203.0.113.44` brute force L5..L189 -> compromise L196 -> admin/export L198, L201; `203.0.113.72` early/late SQLi L29..32 + L222..223; `203.0.113.90` scan L54..69 + path traversal/admin L99..102; `203.0.113.155` 429 burst L159..170; `203.0.113.201` prompt injection attempt L217).
- Normal operational errors (DB timeouts, supplier 502s, null task 500s, deploy 503s, health checks, and `field.officer` single password typo on L238-239) are not called confirmed attacks.
- Untrusted log text (L217 `"Ignore previous instructions..."`) is quarantined inside `<untrusted_log_data>` and never obeyed.

Consequential decisions and reasons:
- Model: `qwen3.5:0.8b` (1.26 GB, #1 suggested model in the brief) with `"think": false` so thinking tokens do not eat the 384-token reply budget; fallback `qwen3:1.7b` / `qwen2.5:1.5b`.
- UI Direction: Operational ledger (`ui-ux-design` Product/operational + Minimalist/Swiss + `anti-generic.md` unslop rules) — Daylight high-contrast paper/ink palette, zero neon AI slop, one-column flow with two big action buttons so "even a drunk man can use it".
- Context-Switching System: 6 bounded context folders (`.harness/design/00..05`) and 4 phase task packets (`phase-1-core`, `phase-2-llm`, `phase-3-web`, `phase-4-verify`), each `<1,100` tokens so active context stays well below 40%. After every phase, the agent prints a bold handoff banner with the exact copy-paste resume prompt for the next chat.

Next increment:
Execute `phase-1-core`: pull/verify `qwen3.5:0.8b`, set up `.venv` from local cached wheels, and implement + test `app/tokenizer.py` and `app/chunker.py`.

Evidence locations:
- `.harness/design/00-master-architecture/SPEC.md`
- `.harness/design/01-tokenizer-and-chunker/SPEC.md`
- `.harness/design/02-local-llm-and-linker/SPEC.md`
- `.harness/design/03-backend-api-and-sse/SPEC.md`
- `.harness/design/04-frontend-ui-contract/SPEC.md`
- `.harness/design/05-verification-and-submission/SPEC.md`
