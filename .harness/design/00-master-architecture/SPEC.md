# 00 — Master System Architecture & Context-Switching Protocol

- **Purpose**: Canonical architecture, resource budgets, directory map, and <40% context-switching workflow.
- **Scope**: Cultive8 Local AI Security Log Analyzer assessment (`/home/ahnaf-zakaria/Desktop/Cultive8`).
- **Update Policy**: Update only when changing system boundaries or phase order.
- **Loading Budget**: ~850 tokens. Load only this file plus the active phase folder.

## 1. Hardware & Assessment Constraints

| Resource | Hard Limit | Design Allocation |
|---|---|---|
| Total Server RAM | 4,096 MB | OS/Python Backend ~120 MB + Ollama `qwen3.5:0.8b` ~1,350 MB = **~1,470 MB total (<36% of 4 GB)** |
| CPU / GPU | 2 vCPU, no GPU | Sequential 1-call-at-a-time queue (`asyncio.Lock`), `"think": false`, compact line encoding |
| Model Context | **2,048 tokens/call** | Prompt (320) + Carried State (250) + Log Chunk (1,050) + Output `num_predict` (384) + Buffer (44) = **2,048 max** |
| Runtime AI | Local model only | Local Ollama HTTP `127.0.0.1:11434` (`qwen3.5:0.8b` primary; `qwen3:1.7b` / `qwen2.5:1.5b` fallback) |

## 2. End-to-End Wiring Diagram

```
[Browser UI (Single Page, Drunk-Man Simple)]
   │  1. POST /api/analyze (multipart .log/.txt OR 1-click sample)
   ▼
[FastAPI / Uvicorn Backend (app/main.py)]
   │  2. Stream upload to disk (runs/<job_id>/input.log) — no extra RAM copies
   ▼
[Tokenizer & Line-Safe Splitter (app/chunker.py)]
   │  3. Load exact BPE vocab/merges from Ollama /api/show (verbose=true)
   │  4. Compact each JSONL line preserving L<num> + all security fields
   │  5. Pack whole lines into chunks <= 1,050 tokens
   ▼
[Sequential Worker & Cross-Chunk Ledger (app/analyzer.py)]
   │  6. For each chunk i..N (1 call at a time):
   │     a. Update rolling per-IP/actor observation ledger
   │     b. Build prompt <= 1,620 input tokens (with <untrusted_log_data> quarantine)
   │     c. Call Ollama /api/generate (model=qwen3.5:0.8b, num_ctx=2048, num_predict=384, think=false, format=json)
   │     d. Repair/validate JSON reply; retry once on timeout/malformed output
   │     e. Save partial findings + token metrics to runs/<job_id>/state.json
   ▼
[Cross-Chunk Report Merger (app/merger.py)]
   │  7. Link events across chunks by (actor_ip, attack_family)
   │  8. Escalate brute-force + later 200 login + admin/export to CRITICAL
   │  9. Filter operational noise (DB timeouts, 502s, single password typo, deploy 503s)
   ▼
[GET /api/jobs/<job_id> -> Live Progress & Final Unified Report]
```

## 3. Repository Layout

```
/home/ahnaf-zakaria/Desktop/Cultive8/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI routes, static mount, RAM telemetry
│   ├── tokenizer.py     # Exact Ollama GGUF BPE tokenizer + fallback counter
│   ├── chunker.py       # Line-safe lossless compaction + 2,048-token budget splitter
│   ├── analyzer.py      # Sequential Ollama caller, retry logic, cross-chunk ledger
│   ├── merger.py        # Cross-chunk event linker, deduplicator, noise separator
│   └── static/
│       └── index.html   # Single-file operational UI (HTML/CSS/JS, zero build step)
├── tests/
│   └── test_pipeline.py # Unit + integration checks for splitter, linker, injection guard
├── runs/                # Per-job saved state (git-ignored)
├── README.md            # Setup, model choice, splitting math, known limits
└── AI_USAGE.md          # Prompts, iterations, token budget plan, AI mistakes fixed
```

## 4. Context-Switching & Handoff Protocol (<40% Occupancy Rule)

Work is split into 4 bounded execution phases, each with its own context folder and harness task ID:

1. **`phase-1-core`**: Environment (`qwen3.5:0.8b`), exact tokenizer (`app/tokenizer.py`), and line-safe chunker (`app/chunker.py`).
   - Context folder: `.harness/design/01-tokenizer-and-chunker/SPEC.md`
2. **`phase-2-llm`**: Local Ollama engine (`app/analyzer.py`) and cross-chunk linker/merger (`app/merger.py`).
   - Context folder: `.harness/design/02-local-llm-and-linker/SPEC.md`
3. **`phase-3-web`**: FastAPI backend (`app/main.py`) and Drunk-Man-Simple UI (`app/static/index.html`).
   - Context folders: `.harness/design/03-backend-api-and-sse/SPEC.md` + `.harness/design/04-frontend-ui-contract/SPEC.md`
4. **`phase-4-verify`**: End-to-end verification (`harness check run`), `README.md`, `AI_USAGE.md`, and git repo readiness.

**Mandatory Handoff Rule**: Whenever a phase completes, the active agent MUST save `harness context checkpoint` and print in **bold** instructions to open a new chat with a copy-paste `"Start from where I left off..."` prompt naming the exact next task ID and spec path.
