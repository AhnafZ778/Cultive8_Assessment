# 03 — Backend API, Memory Safety & Error Handling Specification

- **Purpose**: Exact HTTP contract and reliability rules for `app/main.py`.
- **Scope**: Phase 3 (`phase-3-web`).
- **Update Policy**: Update only if endpoint routes or response JSON fields change.
- **Loading Budget**: ~800 tokens.

## 1. Endpoints Contract

### `GET /`
- Serves `app/static/index.html` (`text/html; charset=utf-8`).

### `GET /api/system`
- Returns current health, active/available local Ollama models, and memory usage:
```json
{
  "ollama_online": true,
  "default_model": "qwen3.5:0.8b",
  "available_models": ["qwen3.5:0.8b", "qwen3:1.7b", "qwen2.5:1.5b", "qwen2:0.5b"],
  "backend_rss_mb": 48.2,
  "ram_limit_mb": 4096,
  "token_limit_per_call": 2048,
  "sample_log_available": true
}
```

### `POST /api/analyze`
- Accepts `multipart/form-data`:
  - `file`: optional uploaded `.log` or `.txt` file.
  - `use_sample`: optional boolean (`"true"`) to analyze `/home/ahnaf-zakaria/Desktop/Cultive8/Cultive8_Workspace_Agrigen_Server.log` directly.
  - `model`: optional string (defaults to `"qwen3.5:0.8b"`, validated against installed local models; never allows cloud models).
- Validation & Error Handling (HTTP `400`):
  - Reject files whose extension is not `.log` or `.txt`.
  - Reject empty files (`0` bytes or `0` non-blank lines).
  - Reject files `> 10 MB` or binary/non-UTF-8 files (decode with `utf-8`, reject if binary null bytes `\x00` present).
- Memory Discipline:
  - Stream uploaded file in 64 KB blocks directly to `runs/<job_id>/input.log`. Do not hold multiple copies of the file in RAM.
- Returns `202 Accepted`:
```json
{
  "job_id": "job-20261107-183000-a1b2",
  "status": "queued",
  "model": "qwen3.5:0.8b",
  "filename": "Cultive8_Workspace_Agrigen_Server.log",
  "total_lines": 258,
  "total_chunks": 15,
  "token_budget": 2048
}
```

### `GET /api/jobs/{job_id}`
- Polled by the frontend every `1000ms` while `status` is `"queued"` or `"running"`.
- Reads from in-memory active state or `runs/{job_id}/state.json` (so it survives even after a backend restart!).
- Response shape:
```json
{
  "job_id": "job-...",
  "status": "queued | running | completed | failed",
  "model": "qwen3.5:0.8b",
  "filename": "Cultive8_Workspace_Agrigen_Server.log",
  "total_lines": 258,
  "current_chunk": 15,
  "total_chunks": 15,
  "elapsed_ms": 28400,
  "backend_rss_mb": 52.1,
  "token_budget": {
    "limit": 2048,
    "max_chunk_tokens_used": 1890,
    "avg_prompt_tokens": 1320,
    "avg_output_tokens": 145,
    "total_calls": 15,
    "retries": 0,
    "failed_chunks": 0
  },
  "chunk_progress": [
    {
      "chunk_index": 1,
      "line_start": 1,
      "line_end": 18,
      "estimated_input_tokens": 1240,
      "ollama_prompt_tokens": 1198,
      "ollama_output_tokens": 132,
      "total_call_tokens": 1330,
      "duration_ms": 1850,
      "status": "ok",
      "findings_in_chunk": 1
    }
  ],
  "report": {
    "summary": "Detected 5 security findings across 258 log lines (15 model calls, max 1,890 / 2,048 tokens per call). Linked cross-file brute force + account compromise on workspace.admin.",
    "findings": [
      {
        "id": "F1",
        "attack_type": "Brute-Force Login Followed by Account Compromise & Data Exfiltration",
        "severity": "Critical",
        "actor_id": "203.0.113.44 (workspace.admin)",
        "CrossChunkLinked": true,
        "chunks_spanned": [1, 2, 3, 4, 5, 6, 7, 9, 11, 12],
        "evidence_lines": [5, 13, 23, 35, 50, 65, 80, 94, 108, 123, 153, 189, 196, 198, 201],
        "evidence_excerpts": [
          {"line": 5, "text": "08:02:30 POST /api/v1/auth/login -> 401 (invalid_password, workspace.admin, python-requests/2.32.3)"},
          {"line": 196, "text": "10:10:10 POST /api/v1/auth/login -> 200 (success, workspace.admin, python-requests/2.32.3)"},
          {"line": 198, "text": "10:11:00 GET /api/v1/admin/users -> 200 (workspace.admin)"},
          {"line": 201, "text": "10:13:30 GET /api/v1/workspaces/7/export?format=csv -> 200 (workspace.admin)"}
        ],
        "reason": "12 automated failed login attempts from 203.0.113.44 across the log were followed by a successful login on line 196, admin user enumeration on line 198, and workspace CSV export on line 201.",
        "suggested_action": "Revoke active sessions for workspace.admin immediately, rotate credentials, block 203.0.113.44, and audit exported workspace 7 data."
      }
    ],
    "ignored_noise": [
      {
        "category": "Single Password Typo (Normal User)",
        "lines": [238, 239],
        "explanation": "198.51.100.96 (field.officer) had 1 failed login followed 30s later by 1 normal browser login."
      }
    ]
  }
}
```
