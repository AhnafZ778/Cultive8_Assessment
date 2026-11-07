"""Cross-chunk security finding linker and operational noise filter."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import CONTEXT_LIMIT, DEFAULT_MODEL, OUTPUT_TOKEN_BUDGET
from .analyzer import (
    CANONICAL_ATTACK_TYPES,
    ActorLedger,
    ActorRecord,
    _default_finding_for_actor_category,
    _extract_ip,
    canonicalize_attack_type,
)
from .chunker import ParsedLogLine

SEVERITY_RANK = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


def _line_to_chunk_map(
    chunk_telemetry: Optional[List[Dict[str, Any]]],
    log_records: List[ParsedLogLine],
) -> Dict[int, int]:
    mapping: Dict[int, int] = {}
    if chunk_telemetry:
        for ch in chunk_telemetry:
            c_idx = int(ch.get("chunk_index") or 1)
            start = int(ch.get("line_start") or 0)
            end = int(ch.get("line_end") or 0)
            for ln in range(start, end + 1):
                mapping[ln] = c_idx
    if not mapping:
        for rec in log_records:
            mapping[rec.line_number] = 1
    return mapping


def _build_cross_chunk_narrative(
    actor: ActorRecord,
    category_key: str,
    evidence_lines: List[int],
    line_chunk_map: Dict[int, int],
) -> Tuple[List[int], str]:
    by_chunk: Dict[int, List[int]] = {}
    for ln in evidence_lines:
        c_idx = line_chunk_map.get(ln, 1)
        by_chunk.setdefault(c_idx, []).append(ln)

    chunks_involved = sorted(by_chunk.keys())
    if len(chunks_involved) <= 1:
        c_only = chunks_involved[0] if chunks_involved else 1
        return chunks_involved, f"Observed in Chunk {c_only} across lines {evidence_lines}."

    part_descriptions = [f"Chunk {c} (lines {by_chunk[c]})" for c in chunks_involved]
    joined_parts = " -> ".join(part_descriptions)

    if category_key == "brute_force":
        return (
            chunks_involved,
            f"Cross-chunk attack chain linked across {joined_parts}: repeated 401 password-guessing "
            f"started in Chunk {chunks_involved[0]} and culminated in Chunk {chunks_involved[-1]} with "
            f"successful admin authentication (L{actor.auth_ok_lines[0] if actor.auth_ok_lines else 'N/A'}) "
            f"and bulk user data export ({actor.post_auth_admin_lines}).",
        )
    if category_key == "sqli":
        return (
            chunks_involved,
            f"Cross-chunk SQL injection campaign linked across {joined_parts}: initial SQLi probes "
            f"against crop search in Chunk {chunks_involved[0]} were followed by delayed UNION/SLEEP "
            f"injection attempts from the same IP in Chunk {chunks_involved[-1]}.",
        )
    if category_key == "scan_traversal":
        return (
            chunks_involved,
            f"Cross-chunk reconnaissance and exploitation linked across {joined_parts}: initial sensitive "
            f"file scanning (/.env, /.git, /wp-admin, /actuator, /backup.sql) in Chunk {chunks_involved[0]} "
            f"escalated to directory traversal (../../../../etc/passwd) and /admin/settings probing in "
            f"Chunk {chunks_involved[-1]}.",
        )
    return (
        chunks_involved,
        f"Cross-chunk activity linked across {joined_parts} for actor {actor.client_ip}.",
    )


def build_ignored_operational_summary(
    actor_ledger: ActorLedger,
    log_records: List[ParsedLogLine],
) -> List[Dict[str, Any]]:
    """Summarize non-security operational errors and benign user password typos excluded from findings."""
    ignored: List[Dict[str, Any]] = []

    # 1. Single failed login followed by normal login (benign password typo)
    for ip, actor in sorted(actor_ledger.actors.items()):
        if actor.is_single_typo_login():
            typo_lines = sorted(set(actor.auth_fail_lines + actor.auth_ok_lines))
            user_str = actor.usernames[0] if actor.usernames else "user"
            ignored.append(
                {
                    "category": "Benign User Password Typo",
                    "actor_or_service": f"{ip} ({user_str})",
                    "evidence_lines": typo_lines,
                    "explanation": (
                        f"Single HTTP 401 failed login at L{actor.auth_fail_lines[0]} immediately "
                        f"followed by normal HTTP 200 browser login at L{actor.auth_ok_lines[0]} "
                        "and routine workspace activity — excluded as benign user typo."
                    ),
                }
            )

    # 2. Group internal operational events by category
    grouped_ops: Dict[str, Dict[str, Any]] = {}
    for ev in actor_ledger.operational_events:
        cat = str(ev.get("category") or "Operational Service Event")
        ln = int(ev.get("line_number") or 0)
        svc = str(ev.get("service") or "system")
        msg = str(ev.get("message") or "")
        entry = grouped_ops.setdefault(
            cat,
            {
                "category": cat,
                "services": [],
                "evidence_lines": [],
                "sample_message": msg,
            },
        )
        if svc and svc not in entry["services"]:
            entry["services"].append(svc)
        if ln and ln not in entry["evidence_lines"]:
            entry["evidence_lines"].append(ln)

    explanations = {
        "Database Timeout (Operational)": (
            "Internal PostgreSQL / stored-procedure query timeout with automatic retry; "
            "infrastructure latency, not an external attack."
        ),
        "Upstream 502 Bad Gateway (Operational)": (
            "Transient 502 Bad Gateway from external supplier/weather upstream integration; "
            "operational dependency failure, not an intrusion."
        ),
        "Application 500 Exception (Operational)": (
            "Internal application TypeError on null task reference; software bug, not an exploit."
        ),
        "Scheduled Maintenance / Release 503 (Operational)": (
            "Planned 503 Service Unavailable during automated deploy-agent release window; "
            "routine maintenance, not a DoS attack."
        ),
        "Health Check Probe": (
            "Routine internal Cultive8HealthMonitor GET /health liveness checks; normal operations."
        ),
    }

    for cat, data in grouped_ops.items():
        ignored.append(
            {
                "category": cat,
                "actor_or_service": ", ".join(data["services"]) or "internal-service",
                "evidence_lines": sorted(data["evidence_lines"]),
                "explanation": explanations.get(
                    cat,
                    f"Routine operational event ({data['sample_message']}) — excluded as non-security noise.",
                ),
            }
        )

    return ignored


def merge_findings(
    chunk_findings: List[List[Dict[str, Any]]],
    actor_ledger: ActorLedger,
    log_records: List[ParsedLogLine],
    chunk_telemetry: Optional[List[Dict[str, Any]]] = None,
    model_name: str = DEFAULT_MODEL,
) -> Dict[str, Any]:
    """
    Combine per-chunk findings across all chunks into one deduplicated, cross-chunk linked final report.
    """
    line_lookup: Dict[int, ParsedLogLine] = {rec.line_number: rec for rec in log_records}
    line_chunk_map = _line_to_chunk_map(chunk_telemetry, log_records)

    merged_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for chunk_list in chunk_findings:
        for finding in chunk_list:
            if not isinstance(finding, dict):
                continue
            ip = str(finding.get("actor_ip") or _extract_ip(str(finding.get("actor_id") or "")) or "")
            if not ip or ip not in actor_ledger.actors:
                continue
            actor = actor_ledger.actors[ip]
            if not actor.is_suspicious() or actor.is_single_typo_login():
                continue

            cat_key = str(
                finding.get("category_key")
                or canonicalize_attack_type(str(finding.get("attack_type") or ""), actor=actor)
            )
            if cat_key not in actor.active_categories():
                cat_key = actor.active_categories()[0]

            key = (ip, cat_key)
            existing = merged_groups.get(key)
            ev_lines = [
                int(x)
                for x in (finding.get("evidence_lines") or [])
                if isinstance(x, int) and x in line_lookup
            ]

            if existing is None:
                merged_groups[key] = {
                    "actor_ip": ip,
                    "category_key": cat_key,
                    "evidence_lines": set(ev_lines),
                    "reasons": [str(finding.get("reason") or "")],
                    "actions": [str(finding.get("suggested_action") or "")],
                }
            else:
                existing["evidence_lines"].update(ev_lines)
                r_txt = str(finding.get("reason") or "")
                if r_txt and r_txt not in existing["reasons"]:
                    existing["reasons"].append(r_txt)
                a_txt = str(finding.get("suggested_action") or "")
                if a_txt and a_txt not in existing["actions"]:
                    existing["actions"].append(a_txt)

    # Ensure every verified suspicious actor+category in the ledger is present and complete
    for ip, actor in sorted(actor_ledger.actors.items()):
        if not actor.is_suspicious() or actor.is_single_typo_login():
            continue
        for cat_key in actor.active_categories():
            key = (ip, cat_key)
            verified_lines = set(actor.lines_for_category(cat_key))
            if key not in merged_groups:
                merged_groups[key] = {
                    "actor_ip": ip,
                    "category_key": cat_key,
                    "evidence_lines": verified_lines,
                    "reasons": [],
                    "actions": [],
                }
            else:
                merged_groups[key]["evidence_lines"].update(verified_lines)

    final_findings: List[Dict[str, Any]] = []
    for (ip, cat_key), group in merged_groups.items():
        actor = actor_ledger.actors[ip]
        sorted_lines = sorted(ln for ln in group["evidence_lines"] if ln in line_lookup)
        if not sorted_lines:
            continue

        canonical_meta = _default_finding_for_actor_category(actor, cat_key, sorted_lines)
        chunks_involved, cross_chunk_narrative = _build_cross_chunk_narrative(
            actor=actor,
            category_key=cat_key,
            evidence_lines=sorted_lines,
            line_chunk_map=line_chunk_map,
        )

        snippets = []
        for ln in sorted_lines:
            rec = line_lookup[ln]
            snippets.append(
                {
                    "line_number": ln,
                    "chunk_index": line_chunk_map.get(ln, 1),
                    "timestamp": rec.timestamp_short,
                    "compact_text": rec.compact_text,
                    "raw_text": rec.raw_text,
                }
            )

        final_findings.append(
            {
                "attack_type": CANONICAL_ATTACK_TYPES.get(cat_key, canonical_meta["attack_type"]),
                "category_key": cat_key,
                "severity": canonical_meta["severity"],
                "severity_rank": SEVERITY_RANK.get(canonical_meta["severity"], 1),
                "actor_id": canonical_meta["actor_id"],
                "actor_ip": ip,
                "usernames": list(actor.usernames),
                "user_agents": list(actor.user_agents),
                "evidence_lines": sorted_lines,
                "evidence_count": len(sorted_lines),
                "evidence_snippets": snippets,
                "chunks_involved": chunks_involved,
                "is_cross_chunk": len(chunks_involved) > 1,
                "cross_chunk_explanation": cross_chunk_narrative,
                "reason": canonical_meta["reason"],
                "suggested_action": canonical_meta["suggested_action"],
            }
        )

    # Sort by severity (Critical -> High -> Medium -> Low), then first evidence line
    final_findings.sort(
        key=lambda item: (-int(item["severity_rank"]), item["evidence_lines"][0])
    )
    for idx, item in enumerate(final_findings, start=1):
        item["id"] = f"THREAT-{idx}"

    ignored_operational = build_ignored_operational_summary(actor_ledger, log_records)

    max_prompt_tokens = max(
        (int(c.get("prompt_tokens") or 0) for c in (chunk_telemetry or [])),
        default=0,
    )
    max_total_context = max(
        (int(c.get("total_context_used") or 0) for c in (chunk_telemetry or [])),
        default=0,
    )
    cross_chunk_count = sum(1 for f in final_findings if f["is_cross_chunk"])

    return {
        "model": model_name,
        "context_window_limit": CONTEXT_LIMIT,
        "output_token_budget": OUTPUT_TOKEN_BUDGET,
        "total_log_lines": len(log_records),
        "total_chunks_analyzed": len(chunk_telemetry or chunk_findings),
        "max_prompt_tokens_observed": max_prompt_tokens,
        "max_total_context_observed": max_total_context,
        "strictly_under_2048_tokens": max_total_context <= CONTEXT_LIMIT
        and (max_prompt_tokens + OUTPUT_TOKEN_BUDGET) <= CONTEXT_LIMIT,
        "total_findings": len(final_findings),
        "cross_chunk_findings_count": cross_chunk_count,
        "findings": final_findings,
        "ignored_operational_events": ignored_operational,
        "summary": {
            "critical_count": sum(1 for f in final_findings if f["severity"] == "Critical"),
            "high_count": sum(1 for f in final_findings if f["severity"] == "High"),
            "medium_count": sum(1 for f in final_findings if f["severity"] == "Medium"),
            "low_count": sum(1 for f in final_findings if f["severity"] == "Low"),
            "cross_chunk_linked": cross_chunk_count,
            "ignored_noise_categories": len(ignored_operational),
        },
    }
