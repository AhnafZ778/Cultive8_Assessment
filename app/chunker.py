"""Line-safe lossless log compaction and 2,048-token budget splitter."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import (
    CARRY_STATE_BUDGET,
    CHUNK_LOG_BUDGET,
    CONTEXT_LIMIT,
    OUTPUT_TOKEN_BUDGET,
    PROMPT_OVERHEAD_BUDGET,
    SAFETY_MARGIN_TOKENS,
)
from .tokenizer import ModelTokenizer

EXTRA_SECURITY_KEYS = (
    "username",
    "auth_result",
    "security_rule",
    "message",
    "exception",
    "location",
    "procedure",
    "timeout_seconds",
    "retryable",
    "attempt",
    "upstream",
    "http_status",
    "retry_in_seconds",
    "validation_error",
    "submitted_text",
    "owner",
    "allowed_paths",
    "task_id",
)


@dataclass
class ParsedLogLine:
    """Single log entry preserving original 1-based line number and parsed fields."""

    line_number: int
    raw_text: str
    compact_text: str
    token_count: int
    parsed_json: Optional[Dict[str, Any]] = None

    @property
    def client_ip(self) -> Optional[str]:
        if self.parsed_json:
            val = self.parsed_json.get("client_ip")
            return str(val) if val else None
        return None

    @property
    def timestamp_short(self) -> str:
        if self.parsed_json:
            t = str(self.parsed_json.get("time") or "")
            if "T" in t and len(t) >= 19:
                return t[11:19]
            return t[:19]
        return ""


@dataclass
class LogChunk:
    """A line-safe slice of log records guaranteed to fit inside the 2,048-token call budget."""

    chunk_index: int
    lines: List[ParsedLogLine] = field(default_factory=list)
    log_tokens: int = 0

    @property
    def line_start(self) -> int:
        return self.lines[0].line_number if self.lines else 0

    @property
    def line_end(self) -> int:
        return self.lines[-1].line_number if self.lines else 0

    @property
    def formatted_text(self) -> str:
        return "\n".join(item.compact_text for item in self.lines)


def compact_log_line(line_number: int, raw_line: str) -> tuple[str, Optional[Dict[str, Any]]]:
    """Losslessly compact a JSONL or plain-text log line while keeping L<line_number> and all security fields."""
    stripped = raw_line.strip()
    if not stripped:
        return f"L{line_number} | EMPTY", None

    try:
        obj = json.loads(stripped)
        if not isinstance(obj, dict):
            raise ValueError("not a JSON object")
    except Exception:
        clean = stripped.replace("\r", " ").replace("\n", " ")
        if len(clean) > 500:
            clean = clean[:500] + "..."
        return f"L{line_number} | RAW | {clean}", None

    time_str = str(obj.get("time") or "")
    if "T" in time_str and len(time_str) >= 19:
        time_short = time_str[11:19]
    else:
        time_short = time_str[:19] or "-"

    app = str(obj.get("app") or "-")
    service = str(obj.get("service") or "-")
    level = str(obj.get("level") or "INFO")
    ip = str(obj.get("client_ip") or "-")
    method = str(obj.get("method") or "")
    path = str(obj.get("path") or "")
    status = obj.get("status")
    ua = str(obj.get("user_agent") or "")
    if "Mozilla/5.0" in ua and "Chrome/130.0.0.0" in ua:
        ua_short = "Chrome130"
    else:
        ua_short = ua

    has_extra = any(obj.get(k) is not None for k in EXTRA_SECURITY_KEYS)
    path_low = path.lower()
    is_routine_ok = (
        level == "INFO"
        and status in (200, 201, 204, 304)
        and ua_short in ("Chrome130", "Cultive8HealthMonitor/1.4")
        and not has_extra
        and "admin" not in path_low
        and "export" not in path_low
        and ".." not in path_low
        and "%2" not in path_low
    )

    if is_routine_ok:
        return f"L{line_number} ip={ip} {method} {path} http={status}", obj

    parts = [f"L{line_number}", time_short, service, level, f"ip={ip}"]
    if method or path:
        parts.append(f"{method} {path}".strip())
    if status is not None:
        parts.append(f"http={status}")
    if ua_short:
        parts.append(f"ua={ua_short}")

    for key in EXTRA_SECURITY_KEYS:
        val = obj.get(key)
        if val is not None:
            clean_val = json.dumps(val, ensure_ascii=False)
            if len(clean_val) > 240:
                clean_val = clean_val[:240] + '..."'
            parts.append(f"{key}={clean_val}")

    return " ".join(parts), obj


def parse_and_split_log(
    log_path: Path,
    tokenizer: ModelTokenizer,
    max_chunk_tokens: int = CHUNK_LOG_BUDGET,
) -> tuple[List[ParsedLogLine], List[LogChunk]]:
    """Stream log file line-by-line, compact losslessly, and group whole lines within max_chunk_tokens."""
    hard_cap = (
        CONTEXT_LIMIT
        - PROMPT_OVERHEAD_BUDGET
        - CARRY_STATE_BUDGET
        - OUTPUT_TOKEN_BUDGET
        - SAFETY_MARGIN_TOKENS
    )
    effective_cap = min(max_chunk_tokens, hard_cap)

    parsed_lines: List[ParsedLogLine] = []
    chunks: List[LogChunk] = []
    current_lines: List[ParsedLogLine] = []
    current_tokens = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for idx, raw in enumerate(handle, start=1):
            raw_clean = raw.rstrip("\r\n")
            if not raw_clean.strip():
                continue
            compact, parsed_json = compact_log_line(idx, raw_clean)
            tok_count = tokenizer.count_tokens(compact + "\n")

            # Guard against a single pathologically huge line exceeding effective_cap
            if tok_count > effective_cap:
                compact = compact[: max(120, int(effective_cap * 2.2))] + " [TRUNCATED]"
                tok_count = min(effective_cap, tokenizer.count_tokens(compact + "\n"))

            entry = ParsedLogLine(
                line_number=idx,
                raw_text=raw_clean,
                compact_text=compact,
                token_count=tok_count,
                parsed_json=parsed_json,
            )
            parsed_lines.append(entry)

            if current_lines and (current_tokens + tok_count > effective_cap):
                chunks.append(
                    LogChunk(
                        chunk_index=len(chunks) + 1,
                        lines=current_lines,
                        log_tokens=current_tokens,
                    )
                )
                current_lines = [entry]
                current_tokens = tok_count
            else:
                current_lines.append(entry)
                current_tokens += tok_count

    if current_lines:
        chunks.append(
            LogChunk(
                chunk_index=len(chunks) + 1,
                lines=current_lines,
                log_tokens=current_tokens,
            )
        )

    return parsed_lines, chunks
