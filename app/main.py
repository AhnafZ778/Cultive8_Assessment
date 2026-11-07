"""FastAPI backend for Cultive8 Local AI Security Log Analyzer.

Implements:
- GET /                  -> Serves Daylight Operational Ledger UI (app/static/index.html)
- GET /api/system        -> Local Ollama health, installed local models, RSS memory, and token cap
- POST /api/analyze      -> Streaming 64 KB upload validation or 1-click sample log analysis
- GET /api/jobs/{job_id} -> Live per-chunk progress, token telemetry, and cross-chunk threat report
"""
from __future__ import annotations

import codecs
import json
import os
import re
import resource
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import UploadFile

from . import (
    CARRY_STATE_BUDGET,
    CONTEXT_LIMIT,
    DEFAULT_MODEL,
    OUTPUT_TOKEN_BUDGET,
)
from .analyzer import (
    CANONICAL_ATTACK_TYPES,
    ActorLedger,
    ActorRecord,
    SequentialLogAnalyzer,
    _default_finding_for_actor_category,
)
from .chunker import ParsedLogLine, parse_and_split_log
from .merger import SEVERITY_RANK
from .tokenizer import OLLAMA_BASE_URL, ModelTokenizer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
INDEX_HTML_PATH = STATIC_DIR / "index.html"
RUNS_DIR = PROJECT_ROOT / "runs"
SAMPLE_LOG_PATH = PROJECT_ROOT / "Cultive8_Workspace_Agrigen_Server.log"

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB hard cap
STREAM_BLOCK_SIZE = 64 * 1024        # 64 KB streaming chunks
RAM_LIMIT_MB = 4096
ALLOWED_EXTENSIONS = {".log", ".txt"}
JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

RUNS_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="Cultive8 Local AI Log Analyzer",
    description="Sequential 2,048-token bounded local LLM security log analyzer",
    version="1.0.0",
)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Single-worker executor guarantees strictly sequential LLM inference (never >1 model call in flight)
_JOB_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cultive8-llm-worker")
_STATE_LOCK = threading.Lock()
_ACTIVE_JOBS: Dict[str, Dict[str, Any]] = {}
_JOB_LINE_CACHE: Dict[str, Dict[int, ParsedLogLine]] = {}


def get_backend_rss_mb() -> float:
    """Read current process RSS in MB from /proc/self/status with getrusage fallback."""
    try:
        status_text = Path("/proc/self/status").read_text(encoding="utf-8")
        for line in status_text.splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) >= 2:
                    kb = float(parts[1])
                    return round(kb / 1024.0, 1)
    except Exception:
        pass
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return round(float(usage.ru_maxrss) / 1024.0, 1)
    except Exception:
        return 0.0


def query_local_ollama_models(base_url: str = OLLAMA_BASE_URL) -> Tuple[bool, List[str]]:
    """Return (ollama_online, local_model_names) excluding any cloud/remote models."""
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=2.5)
        resp.raise_for_status()
        payload = resp.json()
        raw_models = payload.get("models") or []
        local_models: List[str] = []
        for item in raw_models:
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            # Strictly exclude cloud-routed models
            if "cloud" in name.lower() or item.get("remote_host"):
                continue
            if name not in local_models:
                local_models.append(name)

        # Ensure DEFAULT_MODEL is listed first when installed
        if DEFAULT_MODEL in local_models:
            local_models.remove(DEFAULT_MODEL)
            local_models.insert(0, DEFAULT_MODEL)
        elif not local_models:
            local_models = [DEFAULT_MODEL]
        return True, local_models
    except Exception:
        return False, [DEFAULT_MODEL]


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    tmp_path = path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp_path.replace(path)


def _stream_upload_to_disk(upload: UploadFile, dest_path: Path) -> int:
    """
    Stream uploaded file in 64 KB blocks directly to dest_path while enforcing:
    1. Total bytes <= 10 MB
    2. Zero null bytes (\x00)
    3. Valid UTF-8 text encoding (incremental decoder)
    """
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    total_bytes = 0
    file_obj = upload.file

    with dest_path.open("wb") as out_f:
        while True:
            chunk = file_obj.read(STREAM_BLOCK_SIZE)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=400,
                    detail="File exceeds the 10 MB maximum size limit.",
                )
            if b"\x00" in chunk:
                raise HTTPException(
                    status_code=400,
                    detail="Binary file detected (null bytes present). Only UTF-8 .log and .txt files are accepted.",
                )
            try:
                decoder.decode(chunk, final=False)
            except UnicodeDecodeError as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"File is not valid UTF-8 text (byte offset {total_bytes - len(chunk) + exc.start}).",
                ) from exc
            out_f.write(chunk)

        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail="File ends with an incomplete or invalid UTF-8 byte sequence.",
            ) from exc

    if total_bytes == 0:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty (0 bytes).",
        )
    return total_bytes


def _copy_sample_log_in_blocks(src_path: Path, dest_path: Path) -> int:
    total_bytes = 0
    with src_path.open("rb") as src_f, dest_path.open("wb") as dst_f:
        while True:
            block = src_f.read(STREAM_BLOCK_SIZE)
            if not block:
                break
            total_bytes += len(block)
            dst_f.write(block)
    return total_bytes


def _build_partial_findings(
    state: Dict[str, Any],
    line_lookup: Optional[Dict[int, ParsedLogLine]] = None,
) -> List[Dict[str, Any]]:
    """Build live deduplicated findings across completed chunks while a job is still running."""
    chunks = state.get("chunks") or []
    if not chunks:
        return []

    line_to_chunk: Dict[int, int] = {}
    for ch in chunks:
        c_idx = int(ch.get("chunk_index") or 1)
        start = int(ch.get("line_start") or 0)
        end = int(ch.get("line_end") or 0)
        for ln in range(start, end + 1):
            line_to_chunk[ln] = c_idx

    grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for ch in chunks:
        for f in ch.get("findings") or []:
            if not isinstance(f, dict):
                continue
            ip = str(f.get("actor_ip") or f.get("actor_id") or "")
            cat_key = str(f.get("category_key") or f.get("attack_type") or "unknown")
            key = (ip, cat_key)
            ev_lines = [int(x) for x in (f.get("evidence_lines") or []) if isinstance(x, int)]
            if key not in grouped:
                grouped[key] = {
                    "attack_type": f.get("attack_type") or CANONICAL_ATTACK_TYPES.get(cat_key, "Security Finding"),
                    "category_key": cat_key,
                    "severity": f.get("severity") or "Medium",
                    "actor_id": f.get("actor_id") or ip,
                    "actor_ip": ip,
                    "evidence_lines": set(ev_lines),
                    "reason": f.get("reason") or "",
                    "suggested_action": f.get("suggested_action") or "",
                }
            else:
                grouped[key]["evidence_lines"].update(ev_lines)
                if f.get("severity") == "Critical":
                    grouped[key]["severity"] = "Critical"
                if f.get("reason"):
                    grouped[key]["reason"] = f["reason"]
                if f.get("suggested_action"):
                    grouped[key]["suggested_action"] = f["suggested_action"]

    partial_list: List[Dict[str, Any]] = []
    for (_, _), item in grouped.items():
        sorted_lines = sorted(item["evidence_lines"])
        if not sorted_lines:
            continue
        chunks_spanned = sorted({line_to_chunk.get(ln, 1) for ln in sorted_lines})
        excerpts = []
        for ln in sorted_lines:
            rec = line_lookup.get(ln) if line_lookup else None
            excerpts.append(
                {
                    "line": ln,
                    "line_number": ln,
                    "chunk_index": line_to_chunk.get(ln, 1),
                    "timestamp": rec.timestamp_short if rec else "",
                    "text": rec.compact_text if rec else f"L{ln}",
                    "compact_text": rec.compact_text if rec else f"L{ln}",
                    "raw_text": rec.raw_text if rec else "",
                }
            )
        sev = str(item["severity"])
        partial_list.append(
            {
                "attack_type": item["attack_type"],
                "category_key": item["category_key"],
                "severity": sev,
                "severity_rank": SEVERITY_RANK.get(sev, 1),
                "actor_id": item["actor_id"],
                "actor_ip": item["actor_ip"],
                "CrossChunkLinked": len(chunks_spanned) > 1,
                "is_cross_chunk": len(chunks_spanned) > 1,
                "chunks_spanned": chunks_spanned,
                "chunks_involved": chunks_spanned,
                "cross_chunk_explanation": (
                    f"Linked across Chunks {chunks_spanned} so far."
                    if len(chunks_spanned) > 1
                    else f"Observed in Chunk {chunks_spanned[0]}."
                ),
                "evidence_lines": sorted_lines,
                "evidence_count": len(sorted_lines),
                "evidence_excerpts": excerpts,
                "evidence_snippets": excerpts,
                "reason": item["reason"],
                "suggested_action": item["suggested_action"],
            }
        )

    partial_list.sort(key=lambda x: (-int(x["severity_rank"]), x["evidence_lines"][0]))
    for idx, f_obj in enumerate(partial_list, start=1):
        f_obj["id"] = f"F{idx}"
    return partial_list


def format_job_response(state: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize in-memory or disk state.json into the exact API response contract."""
    job_id = str(state.get("job_id") or "")
    status = str(state.get("status") or "queued")
    model = str(state.get("model") or DEFAULT_MODEL)
    filename = str(state.get("filename") or state.get("log_file") or "input.log")
    total_lines = int(state.get("total_lines") or 0)
    total_chunks = int(state.get("total_chunks") or 0)
    completed_chunks = int(state.get("completed_chunks") or 0)
    current_chunk = int(state.get("current_chunk") or completed_chunks or 0)

    started_at = float(state.get("started_at") or time.time())
    updated_at = float(state.get("updated_at") or time.time())
    end_ts = updated_at if status in ("completed", "failed") else time.time()
    elapsed_ms = max(0, int(round((end_ts - started_at) * 1000)))

    raw_chunks: List[Dict[str, Any]] = state.get("chunks") or []
    chunk_progress: List[Dict[str, Any]] = []
    prompt_tok_list: List[int] = []
    output_tok_list: List[int] = []
    total_tok_list: List[int] = []
    retries_total = 0
    failed_chunks = 0

    for ch in raw_chunks:
        p_tok = int(ch.get("prompt_tokens") or 0)
        r_tok = int(ch.get("response_tokens") or 0)
        t_tok = int(ch.get("total_context_used") or (p_tok + r_tok))
        within_limit = bool(ch.get("within_2048_limit", t_tok <= CONTEXT_LIMIT))
        attempts = int(ch.get("attempts") or 1)
        retries_total += max(0, attempts - 1)
        if not within_limit:
            failed_chunks += 1

        prompt_tok_list.append(p_tok)
        output_tok_list.append(r_tok)
        total_tok_list.append(t_tok)

        duration_ms = int(round(float(ch.get("elapsed_seconds") or 0.0) * 1000))
        chunk_progress.append(
            {
                "chunk_index": int(ch.get("chunk_index") or 1),
                "line_start": int(ch.get("line_start") or 1),
                "line_end": int(ch.get("line_end") or 1),
                "line_count": int(ch.get("line_count") or 0),
                "chunk_log_tokens": int(ch.get("chunk_log_tokens") or 0),
                "carry_state_tokens": int(ch.get("carry_state_tokens") or 0),
                "estimated_input_tokens": p_tok,
                "ollama_prompt_tokens": p_tok,
                "ollama_output_tokens": r_tok,
                "prompt_tokens": p_tok,
                "response_tokens": r_tok,
                "output_budget_tokens": int(ch.get("output_budget_tokens") or OUTPUT_TOKEN_BUDGET),
                "total_call_tokens": t_tok,
                "total_context_used": t_tok,
                "max_reserved_context": int(ch.get("max_reserved_context") or (p_tok + OUTPUT_TOKEN_BUDGET)),
                "within_2048_limit": within_limit,
                "duration_ms": duration_ms,
                "attempts": attempts,
                "status": "ok" if within_limit else "over_budget",
                "findings_in_chunk": len(ch.get("findings") or []),
                "carry_state_text": str(ch.get("carry_state_text") or ""),
            }
        )

    max_chunk_tokens_used = max(total_tok_list, default=0)
    max_prompt_tokens_used = max(prompt_tok_list, default=0)
    avg_prompt_tokens = int(round(sum(prompt_tok_list) / len(prompt_tok_list))) if prompt_tok_list else 0
    avg_output_tokens = int(round(sum(output_tok_list) / len(output_tok_list))) if output_tok_list else 0

    token_budget = {
        "limit": CONTEXT_LIMIT,
        "output_budget": OUTPUT_TOKEN_BUDGET,
        "carry_state_budget": CARRY_STATE_BUDGET,
        "max_chunk_tokens_used": max_chunk_tokens_used,
        "max_prompt_tokens_used": max_prompt_tokens_used,
        "avg_prompt_tokens": avg_prompt_tokens,
        "avg_output_tokens": avg_output_tokens,
        "total_calls": len(raw_chunks),
        "retries": retries_total,
        "failed_chunks": failed_chunks,
        "strictly_under_2048": failed_chunks == 0 and max_chunk_tokens_used <= CONTEXT_LIMIT,
    }

    final_report = state.get("final_report")
    report_payload: Optional[Dict[str, Any]] = None

    if isinstance(final_report, dict):
        formatted_findings: List[Dict[str, Any]] = []
        for idx, f in enumerate(final_report.get("findings") or [], start=1):
            snippets = f.get("evidence_snippets") or []
            excerpts = [
                {
                    "line": int(s.get("line_number") or s.get("line") or 0),
                    "line_number": int(s.get("line_number") or s.get("line") or 0),
                    "chunk_index": int(s.get("chunk_index") or 1),
                    "timestamp": str(s.get("timestamp") or ""),
                    "text": str(s.get("compact_text") or s.get("text") or ""),
                    "compact_text": str(s.get("compact_text") or s.get("text") or ""),
                    "raw_text": str(s.get("raw_text") or ""),
                }
                for s in snippets
            ]
            chunks_involved = list(f.get("chunks_involved") or f.get("chunks_spanned") or [])
            is_cross = bool(f.get("is_cross_chunk", len(chunks_involved) > 1))
            formatted_findings.append(
                {
                    "id": str(f.get("id") or f"F{idx}"),
                    "code": f"F{idx}",
                    "attack_type": str(f.get("attack_type") or ""),
                    "category_key": str(f.get("category_key") or ""),
                    "severity": str(f.get("severity") or "Medium"),
                    "actor_id": str(f.get("actor_id") or ""),
                    "actor_ip": str(f.get("actor_ip") or ""),
                    "usernames": list(f.get("usernames") or []),
                    "user_agents": list(f.get("user_agents") or []),
                    "CrossChunkLinked": is_cross,
                    "is_cross_chunk": is_cross,
                    "chunks_spanned": chunks_involved,
                    "chunks_involved": chunks_involved,
                    "cross_chunk_explanation": str(f.get("cross_chunk_explanation") or ""),
                    "evidence_lines": list(f.get("evidence_lines") or []),
                    "evidence_count": len(f.get("evidence_lines") or []),
                    "evidence_excerpts": excerpts,
                    "evidence_snippets": excerpts,
                    "reason": str(f.get("reason") or ""),
                    "suggested_action": str(f.get("suggested_action") or ""),
                }
            )

        raw_ignored = final_report.get("ignored_operational_events") or []
        ignored_noise: List[Dict[str, Any]] = []
        for item in raw_ignored:
            ev_lines = list(item.get("evidence_lines") or item.get("lines") or [])
            ignored_noise.append(
                {
                    "category": str(item.get("category") or "Operational Noise"),
                    "actor_or_service": str(item.get("actor_or_service") or "system"),
                    "lines": ev_lines,
                    "evidence_lines": ev_lines,
                    "explanation": str(item.get("explanation") or ""),
                }
            )

        cross_cnt = sum(1 for item in formatted_findings if item["CrossChunkLinked"])
        summary_text = (
            f"Detected {len(formatted_findings)} confirmed security findings across {total_lines} log lines "
            f"({len(raw_chunks)} sequential local LLM calls, max {max_chunk_tokens_used:,} / {CONTEXT_LIMIT:,} tokens per call). "
            f"Linked {cross_cnt} cross-chunk attack chains and filtered {len(ignored_noise)} non-security operational noise categories."
        )
        report_payload = {
            "summary": summary_text,
            "summary_counts": final_report.get("summary") or {},
            "total_findings": len(formatted_findings),
            "cross_chunk_findings_count": cross_cnt,
            "max_prompt_tokens_observed": max_prompt_tokens_used,
            "max_total_context_observed": max_chunk_tokens_used,
            "strictly_under_2048_tokens": token_budget["strictly_under_2048"],
            "findings": formatted_findings,
            "ignored_noise": ignored_noise,
            "ignored_operational_events": ignored_noise,
        }
    elif raw_chunks:
        line_lookup = _JOB_LINE_CACHE.get(job_id)
        partial_findings = _build_partial_findings(state, line_lookup=line_lookup)
        cross_cnt = sum(1 for item in partial_findings if item["CrossChunkLinked"])
        report_payload = {
            "summary": (
                f"In progress: {completed_chunks} of {total_chunks} chunks analyzed "
                f"({len(partial_findings)} provisional findings identified so far, "
                f"max {max_chunk_tokens_used:,} / {CONTEXT_LIMIT:,} tokens per call)."
            ),
            "summary_counts": {
                "critical_count": sum(1 for f in partial_findings if f["severity"] == "Critical"),
                "high_count": sum(1 for f in partial_findings if f["severity"] == "High"),
                "medium_count": sum(1 for f in partial_findings if f["severity"] == "Medium"),
                "low_count": sum(1 for f in partial_findings if f["severity"] == "Low"),
                "cross_chunk_linked": cross_cnt,
                "ignored_noise_categories": 0,
            },
            "total_findings": len(partial_findings),
            "cross_chunk_findings_count": cross_cnt,
            "max_prompt_tokens_observed": max_prompt_tokens_used,
            "max_total_context_observed": max_chunk_tokens_used,
            "strictly_under_2048_tokens": token_budget["strictly_under_2048"],
            "findings": partial_findings,
            "ignored_noise": [],
            "ignored_operational_events": [],
        }

    return {
        "job_id": job_id,
        "status": status,
        "error": state.get("error"),
        "model": model,
        "filename": filename,
        "total_lines": total_lines,
        "current_chunk": current_chunk,
        "completed_chunks": completed_chunks,
        "total_chunks": total_chunks,
        "elapsed_ms": elapsed_ms,
        "backend_rss_mb": get_backend_rss_mb(),
        "token_budget": token_budget,
        "chunk_progress": chunk_progress,
        "report": report_payload,
        "final_report": final_report,
    }


def _run_analysis_job(
    job_id: str,
    input_log_path: Path,
    original_filename: str,
    model_name: str,
) -> None:
    """Background worker that executes SequentialLogAnalyzer one chunk at a time."""
    state_path = RUNS_DIR / job_id / "state.json"

    def _on_chunk_update(live_state: Dict[str, Any]) -> None:
        live_state["filename"] = original_filename
        live_state["log_file"] = original_filename
        _atomic_write_json(state_path, live_state)
        with _STATE_LOCK:
            _ACTIVE_JOBS[job_id] = live_state

    try:
        analyzer = SequentialLogAnalyzer(model_name=model_name, base_url=OLLAMA_BASE_URL)
        final_state = analyzer.analyze_log_file(
            log_path=input_log_path,
            job_id=job_id,
            runs_dir=RUNS_DIR,
            on_chunk_complete=_on_chunk_update,
        )
        final_state["filename"] = original_filename
        final_state["log_file"] = original_filename
        _atomic_write_json(state_path, final_state)
        with _STATE_LOCK:
            _ACTIVE_JOBS[job_id] = final_state
    except Exception as exc:
        with _STATE_LOCK:
            failed_state = dict(_ACTIVE_JOBS.get(job_id) or {})
            failed_state.update(
                {
                    "job_id": job_id,
                    "status": "failed",
                    "error": str(exc),
                    "filename": original_filename,
                    "log_file": original_filename,
                    "updated_at": time.time(),
                }
            )
            _ACTIVE_JOBS[job_id] = failed_state
        try:
            _atomic_write_json(state_path, failed_state)
        except Exception:
            pass
    finally:
        # Release line cache once final_report is persisted to keep RAM footprint flat
        with _STATE_LOCK:
            _JOB_LINE_CACHE.pop(job_id, None)


@app.get("/", response_class=HTMLResponse)
async def serve_index() -> Response:
    """Serve the single-page Daylight Operational Ledger UI."""
    if not INDEX_HTML_PATH.is_file():
        return HTMLResponse(
            content="<h1>UI missing: app/static/index.html not found</h1>",
            status_code=500,
        )
    return FileResponse(
        path=str(INDEX_HTML_PATH),
        media_type="text/html; charset=utf-8",
    )


@app.get("/api/system")
async def get_system_status() -> Dict[str, Any]:
    """Return local Ollama connectivity, available local models, RSS memory, and hard caps."""
    ollama_online, available_models = query_local_ollama_models()
    return {
        "ollama_online": ollama_online,
        "default_model": DEFAULT_MODEL,
        "available_models": available_models,
        "backend_rss_mb": get_backend_rss_mb(),
        "ram_limit_mb": RAM_LIMIT_MB,
        "token_limit_per_call": CONTEXT_LIMIT,
        "output_token_budget": OUTPUT_TOKEN_BUDGET,
        "carry_state_budget": CARRY_STATE_BUDGET,
        "sample_log_available": SAMPLE_LOG_PATH.is_file(),
        "sample_log_filename": SAMPLE_LOG_PATH.name,
    }


@app.post("/api/analyze", status_code=202)
async def start_analysis(request: Request) -> JSONResponse:
    """
    Validate and stream uploaded .log/.txt file (or copy sample log) to runs/<job_id>/input.log,
    pre-calculate chunk count under the 2,048-token budget, and enqueue sequential local analysis.
    """
    content_type = (request.headers.get("content-type") or "").lower()
    upload_file: Optional[UploadFile] = None
    use_sample_raw: Any = None
    model_raw: Any = None

    if "application/json" in content_type:
        try:
            body = await request.json()
            if isinstance(body, dict):
                use_sample_raw = body.get("use_sample")
                model_raw = body.get("model")
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON request body.") from exc
    else:
        try:
            form = await request.form()
            file_field = form.get("file")
            if isinstance(file_field, UploadFile) or hasattr(file_field, "filename"):
                upload_file = file_field  # type: ignore[assignment]
            use_sample_raw = form.get("use_sample")
            model_raw = form.get("model")
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail="Expected multipart/form-data with 'file' or 'use_sample=true'.",
            ) from exc

    use_sample = str(use_sample_raw or "").strip().lower() in ("true", "1", "yes", "on")
    selected_model = str(model_raw or DEFAULT_MODEL).strip() or DEFAULT_MODEL

    # Never allow cloud models
    if "cloud" in selected_model.lower():
        raise HTTPException(
            status_code=400,
            detail=f"Cloud models ('{selected_model}') are strictly forbidden. Use a local Ollama model such as '{DEFAULT_MODEL}'.",
        )

    ollama_online, available_models = query_local_ollama_models()
    if ollama_online and available_models and selected_model not in available_models:
        raise HTTPException(
            status_code=400,
            detail=f"Model '{selected_model}' is not installed locally. Available local models: {', '.join(available_models)}.",
        )

    has_upload = upload_file is not None and bool(getattr(upload_file, "filename", ""))
    if not use_sample and not has_upload:
        raise HTTPException(
            status_code=400,
            detail="Please provide a .log or .txt file upload, or set use_sample=true to analyze the supplied Cultive8 log.",
        )

    ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    job_id = f"job-{ts_slug}-{uuid.uuid4().hex[:6]}"
    job_dir = RUNS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    input_log_path = job_dir / "input.log"

    try:
        if has_upload and upload_file is not None:
            original_filename = Path(upload_file.filename or "").name
            ext = Path(original_filename).suffix.lower()
            if ext not in ALLOWED_EXTENSIONS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported file extension '{ext or '(none)'}'. Only .log and .txt text files are accepted.",
                )
            _stream_upload_to_disk(upload_file, input_log_path)
        else:
            if not SAMPLE_LOG_PATH.is_file():
                raise HTTPException(
                    status_code=400,
                    detail=f"Sample log file not found at {SAMPLE_LOG_PATH}.",
                )
            original_filename = SAMPLE_LOG_PATH.name
            _copy_sample_log_in_blocks(SAMPLE_LOG_PATH, input_log_path)

        # Parse and pre-split log lines to reject blank-only files and report exact line/chunk counts
        tokenizer = ModelTokenizer(model_name=selected_model, base_url=OLLAMA_BASE_URL)
        parsed_lines, chunks = parse_and_split_log(input_log_path, tokenizer)
        if not parsed_lines or not chunks:
            raise HTTPException(
                status_code=400,
                detail="Log file contains 0 non-blank log lines.",
            )

        total_lines = parsed_lines[-1].line_number
        total_chunks = len(chunks)
        now = time.time()

        initial_state: Dict[str, Any] = {
            "job_id": job_id,
            "status": "queued",
            "model": selected_model,
            "tokenizer_backend": tokenizer.backend_source,
            "filename": original_filename,
            "log_file": original_filename,
            "log_path": str(input_log_path.resolve()),
            "total_lines": total_lines,
            "total_chunks": total_chunks,
            "completed_chunks": 0,
            "current_chunk": 0,
            "context_limit": CONTEXT_LIMIT,
            "output_token_budget": OUTPUT_TOKEN_BUDGET,
            "chunks": [],
            "actor_ledger": {"actors": {}, "operational_events": []},
            "chunk_findings": [],
            "final_report": None,
            "started_at": now,
            "updated_at": now,
        }
        _atomic_write_json(job_dir / "state.json", initial_state)

        with _STATE_LOCK:
            _ACTIVE_JOBS[job_id] = initial_state
            _JOB_LINE_CACHE[job_id] = {rec.line_number: rec for rec in parsed_lines}

        _JOB_EXECUTOR.submit(
            _run_analysis_job,
            job_id,
            input_log_path,
            original_filename,
            selected_model,
        )

        return JSONResponse(
            status_code=202,
            content={
                "job_id": job_id,
                "status": "queued",
                "model": selected_model,
                "filename": original_filename,
                "total_lines": total_lines,
                "total_chunks": total_chunks,
                "token_budget": CONTEXT_LIMIT,
            },
        )
    except HTTPException:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(
            status_code=400,
            detail=f"Failed to initialize log analysis job: {exc}",
        ) from exc


@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str) -> Dict[str, Any]:
    """Return live or completed job progress, token telemetry, and cross-chunk threat report."""
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format.")

    with _STATE_LOCK:
        mem_state = _ACTIVE_JOBS.get(job_id)

    if mem_state is not None:
        return format_job_response(mem_state)

    state_path = RUNS_DIR / job_id / "state.json"
    if not state_path.is_file():
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")

    try:
        disk_state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to read state for job '{job_id}': {exc}",
        ) from exc

    return format_job_response(disk_state)
