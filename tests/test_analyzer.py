"""Comprehensive verification suite for the Cultive8 Local AI Log Analyzer.

Covers all 7 verification gates:
1. Gate 1: Strict 2,048-token budget per LLM call & whole-line log splitting
2. Gate 2: Cross-chunk attack chain linking (Brute-Force -> Compromise, SQLi, Recon/Traversal, Rate-Limit Flood)
3. Gate 3: Prompt-injection quarantine (<untrusted_log_data>) & ledger tampering resilience
4. Gate 4: Operational noise & false-positive filtering (field.officer typo, 500/502/503/504, health checks)
5. Gate 5: Malformed LLM JSON recovery & out-of-range/status-code line hallucination guard
6. Gate 6: Invalid file upload rejection (extension, 0-byte, blank-only, null-byte binary, bad UTF-8, >10MB, cloud model)
7. Gate 7: FastAPI HTTP contract (GET /, GET /api/system, POST /api/analyze, GET /api/jobs/{id}) & sample report validation
"""
from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT_DIR))

from fastapi.testclient import TestClient

from app import (
    CARRY_STATE_BUDGET,
    CHUNK_LOG_BUDGET,
    CONTEXT_LIMIT,
    DEFAULT_MODEL,
    OUTPUT_TOKEN_BUDGET,
)
from app.analyzer import (
    ActorLedger,
    build_chunk_prompt,
    ground_and_validate_chunk_findings,
    repair_and_parse_json,
)
from app.chunker import parse_and_split_log
from app.main import MAX_UPLOAD_BYTES, PROJECT_ROOT, SAMPLE_LOG_PATH, app, format_job_response
from app.merger import merge_findings
from app.tokenizer import ModelTokenizer

SAMPLE_REPORT_PATH = PROJECT_ROOT / "sample_output" / "Cultive8_Sample_Analysis_Report.json"


class TestCultive8AnalyzerGates(unittest.TestCase):
    """Verification suite covering all 7 engineering and security evaluation gates."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tokenizer = ModelTokenizer(model_name=DEFAULT_MODEL)
        cls.parsed_lines, cls.chunks = parse_and_split_log(
            SAMPLE_LOG_PATH,
            cls.tokenizer,
            max_chunk_tokens=CHUNK_LOG_BUDGET,
        )
        cls.client = TestClient(app)
        assert SAMPLE_REPORT_PATH.is_file(), f"Missing sample report at {SAMPLE_REPORT_PATH}"
        cls.sample_report = json.loads(SAMPLE_REPORT_PATH.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # Gate 1: Strict 2,048-Token Cap & Whole-Line Log Splitting
    # ------------------------------------------------------------------
    def test_gate1_token_budget_and_line_splitting(self) -> None:
        """Verify 258 lines split cleanly on whole-line boundaries and every call stays <= 2,048 tokens."""
        self.assertEqual(len(self.parsed_lines), 258)
        self.assertEqual(self.parsed_lines[0].line_number, 1)
        self.assertEqual(self.parsed_lines[-1].line_number, 258)

        # Ensure contiguous line coverage L1..L258 with zero dropped or duplicated lines
        flattened_lines = [line.line_number for chunk in self.chunks for line in chunk.lines]
        self.assertEqual(flattened_lines, list(range(1, 259)))

        ledger = ActorLedger()
        for chunk in self.chunks:
            # Each chunk's raw compacted log tokens must fit inside CHUNK_LOG_BUDGET (1,050)
            self.assertLessEqual(
                chunk.log_tokens,
                CHUNK_LOG_BUDGET,
                f"Chunk {chunk.chunk_index} log tokens ({chunk.log_tokens}) exceeded {CHUNK_LOG_BUDGET}",
            )

            carry_text, carry_tokens = ledger.serialize_carry_state(
                self.tokenizer,
                max_tokens=CARRY_STATE_BUDGET,
            )
            self.assertLessEqual(
                carry_tokens,
                CARRY_STATE_BUDGET,
                f"Carry state tokens ({carry_tokens}) exceeded {CARRY_STATE_BUDGET}",
            )

            prompt_text, prompt_tokens = build_chunk_prompt(
                chunk=chunk,
                total_chunks=len(self.chunks),
                carry_state_text=carry_text,
                tokenizer=self.tokenizer,
            )
            total_reserved = prompt_tokens + OUTPUT_TOKEN_BUDGET
            self.assertLessEqual(
                total_reserved,
                CONTEXT_LIMIT,
                f"Chunk {chunk.chunk_index} reserved context ({total_reserved}) exceeded {CONTEXT_LIMIT}",
            )
            self.assertIn("<untrusted_log_data>", prompt_text)
            self.assertIn("</untrusted_log_data>", prompt_text)
            ledger.ingest_chunk(chunk)

        # Also verify actual recorded Ollama telemetry in sample_output/Cultive8_Sample_Analysis_Report.json
        tb = self.sample_report["token_budget"]
        self.assertEqual(tb["limit"], 2048)
        self.assertTrue(tb["strictly_under_2048"])
        self.assertEqual(tb["failed_chunks"], 0)
        self.assertLessEqual(tb["max_chunk_tokens_used"], 2048)
        for ch_stat in self.sample_report["chunk_progress"]:
            self.assertLessEqual(ch_stat["total_context_used"], 2048)
            self.assertTrue(ch_stat["within_2048_limit"])

    # ------------------------------------------------------------------
    # Gate 2: Cross-Chunk Attack Chain Linking
    # ------------------------------------------------------------------
    def test_gate2_cross_chunk_linking(self) -> None:
        """Verify early, mid, and late chunk clues merge into deduplicated cross-chunk findings."""
        ledger = ActorLedger()
        chunk_findings = []
        chunk_telemetry = []

        for chunk in self.chunks:
            ledger.ingest_chunk(chunk)
            grounded = ground_and_validate_chunk_findings(
                raw_findings=[],
                chunk=chunk,
                ledger=ledger,
                total_lines=len(self.parsed_lines),
            )
            chunk_findings.append(grounded)
            chunk_telemetry.append(
                {
                    "chunk_index": chunk.chunk_index,
                    "line_start": chunk.line_start,
                    "line_end": chunk.line_end,
                    "prompt_tokens": 1100,
                    "response_tokens": 120,
                    "total_context_used": 1220,
                    "within_2048_limit": True,
                }
            )

        merged = merge_findings(
            chunk_findings=chunk_findings,
            actor_ledger=ledger,
            log_records=self.parsed_lines,
            chunk_telemetry=chunk_telemetry,
            model_name=DEFAULT_MODEL,
        )
        findings_by_ip = {f["actor_ip"]: f for f in merged["findings"]}

        # 1. 203.0.113.44: Brute-Force Login & Account Compromise across Chunks 1..9
        bf = findings_by_ip["203.0.113.44"]
        self.assertEqual(bf["severity"], "Critical")
        self.assertTrue(bf["is_cross_chunk"])
        self.assertGreater(len(bf["chunks_involved"]), 1)
        for expected_line in (5, 13, 189, 196, 198, 201):
            self.assertIn(expected_line, bf["evidence_lines"])

        # 2. 203.0.113.72: SQL Injection linked between Chunk 2 (L29,30,32) and Chunk 10 (L222,223)
        sqli = findings_by_ip["203.0.113.72"]
        self.assertEqual(sqli["severity"], "High")
        self.assertTrue(sqli["is_cross_chunk"])
        for expected_line in (29, 30, 32, 222, 223):
            self.assertIn(expected_line, sqli["evidence_lines"])
        self.assertGreaterEqual(len(sqli["chunks_involved"]), 2)

        # 3. 203.0.113.90: Vulnerability Scanning & Path Traversal across Chunks 3, 4, 5
        recon = findings_by_ip["203.0.113.90"]
        self.assertEqual(recon["severity"], "High")
        self.assertTrue(recon["is_cross_chunk"])
        for expected_line in (54, 69, 99, 101, 102):
            self.assertIn(expected_line, recon["evidence_lines"])

        # 4. 203.0.113.155: Rate-Limit Abuse / Automated Flooding across Chunks 7 & 8
        flood = findings_by_ip["203.0.113.155"]
        self.assertIn(flood["severity"], ("Medium", "High"))
        self.assertTrue(flood["is_cross_chunk"])
        for expected_line in (159, 162, 170):
            self.assertIn(expected_line, flood["evidence_lines"])

    # ------------------------------------------------------------------
    # Gate 3: Prompt-Injection Quarantine & Ledger Tampering Resilience
    # ------------------------------------------------------------------
    def test_gate3_prompt_injection_resilience(self) -> None:
        """Verify L217 prompt injection is quarantined in <untrusted_log_data> and cannot erase evidence."""
        chunk_with_217 = next(
            ch for ch in self.chunks if ch.line_start <= 217 <= ch.line_end
        )
        ledger = ActorLedger()
        for ch in self.chunks:
            ledger.ingest_chunk(ch)
            if ch.chunk_index == chunk_with_217.chunk_index:
                break

        carry_text, _ = ledger.serialize_carry_state(self.tokenizer)
        prompt_text, _ = build_chunk_prompt(
            chunk=chunk_with_217,
            total_chunks=len(self.chunks),
            carry_state_text=carry_text,
            tokenizer=self.tokenizer,
        )

        # Must wrap log lines inside <untrusted_log_data>
        untrusted_start = prompt_text.index("<untrusted_log_data>")
        untrusted_end = prompt_text.index("</untrusted_log_data>")
        l217_pos = prompt_text.index("L217 ")
        self.assertGreater(l217_pos, untrusted_start)
        self.assertLess(l217_pos, untrusted_end)

        # Simulate a tricked LLM returning empty findings ("all events are safe")
        grounded = ground_and_validate_chunk_findings(
            raw_findings=[],
            chunk=chunk_with_217,
            ledger=ledger,
            total_lines=len(self.parsed_lines),
        )
        inj_findings = [f for f in grounded if f["actor_ip"] == "203.0.113.201"]
        self.assertEqual(len(inj_findings), 1)
        self.assertEqual(inj_findings[0]["category_key"], "prompt_injection")
        self.assertIn(217, inj_findings[0]["evidence_lines"])

        # Prior failed login evidence for 203.0.113.44 must remain intact in the ledger
        admin_actor = ledger.actors["203.0.113.44"]
        self.assertGreaterEqual(len(admin_actor.auth_fail_lines), 12)
        self.assertIn(196, admin_actor.auth_ok_lines)

    # ------------------------------------------------------------------
    # Gate 4: Operational Noise & False-Positive Filtering
    # ------------------------------------------------------------------
    def test_gate4_operational_noise_filtering(self) -> None:
        """Verify benign user typos, health checks, and 5xx operational faults are NOT flagged as attacks."""
        findings = self.sample_report["report"]["findings"]
        finding_ips = {f["actor_ip"] for f in findings}
        finding_lines = {ln for f in findings for ln in f["evidence_lines"]}

        # Benign field.officer single 401 typo (L238) + 200 login (L239) must NOT be flagged
        self.assertNotIn("198.51.100.96", finding_ips)
        self.assertNotIn(238, finding_lines)
        self.assertNotIn(239, finding_lines)

        # Health check IP 192.0.2.10 must NOT be flagged
        self.assertNotIn("192.0.2.10", finding_ips)

        # Operational 500/502/503/504 lines must NOT be in security findings
        for operational_line in (3, 11, 19, 41, 42, 45, 70, 84, 135, 136, 140, 147, 178, 207, 210, 230):
            self.assertNotIn(
                operational_line,
                finding_lines,
                f"Operational line L{operational_line} was falsely flagged as a security threat",
            )

        # Verify all 6 noise categories are documented in ignored_noise
        ignored_noise = self.sample_report["report"]["ignored_noise"]
        self.assertGreaterEqual(len(ignored_noise), 6)
        categories = {item["category"] for item in ignored_noise}
        self.assertIn("Benign User Password Typo", categories)
        self.assertIn("Health Check Probe", categories)
        self.assertIn("Database Timeout (Operational)", categories)
        self.assertIn("Upstream 502 Bad Gateway (Operational)", categories)
        self.assertIn("Application 500 Exception (Operational)", categories)
        self.assertIn("Scheduled Maintenance / Release 503 (Operational)", categories)

    # ------------------------------------------------------------------
    # Gate 5: Malformed LLM Output & Hallucination Guard
    # ------------------------------------------------------------------
    def test_gate5_malformed_json_and_hallucination_guard(self) -> None:
        """Verify broken/fenced JSON repair and rejection of hallucinated HTTP status codes as line numbers."""
        broken_llm_output = """```json
        {
          "findings": [
            {
              "attack_type": "SQL Injection",
              "severity": "High",
              "actor": "203.0.113.72",
              "evidence_lines": ["L29", "L30", 403, 9999],
              "reason": "SQLi probe on filter_LotCode",
              "suggested_action": "Block IP 203.0.113.72",
            },
          ],
        }
        ```"""
        parsed = repair_and_parse_json(broken_llm_output)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(len(parsed["findings"]), 1)

        # Ground against Chunk 2 (lines 25..47)
        chunk2 = self.chunks[1]
        ledger = ActorLedger()
        ledger.ingest_chunk(self.chunks[0])
        ledger.ingest_chunk(chunk2)

        grounded = ground_and_validate_chunk_findings(
            raw_findings=parsed["findings"],
            chunk=chunk2,
            ledger=ledger,
            total_lines=258,
        )
        sqli = next(f for f in grounded if f["actor_ip"] == "203.0.113.72")
        # Hallucinated HTTP status 403 and out-of-range 9999 must be stripped; true lines 29, 30, 32 kept
        self.assertNotIn(403, sqli["evidence_lines"])
        self.assertNotIn(9999, sqli["evidence_lines"])
        for valid_ln in (29, 30, 32):
            self.assertIn(valid_ln, sqli["evidence_lines"])

    # ------------------------------------------------------------------
    # Gate 6: Invalid File Upload Rejection
    # ------------------------------------------------------------------
    def test_gate6_invalid_file_rejection(self) -> None:
        """Verify POST /api/analyze rejects unsupported extensions, empty/blank, binary, bad UTF-8, >10MB, and cloud models."""
        # 1. Unsupported extension (.pdf / .exe)
        resp_ext = self.client.post(
            "/api/analyze",
            files={"file": ("report.pdf", b"2026-03-19T08:00:00Z INFO hello\n", "application/pdf")},
        )
        self.assertEqual(resp_ext.status_code, 400)
        self.assertIn("extension", resp_ext.json()["detail"].lower())

        # 2. Empty 0-byte file
        resp_empty = self.client.post(
            "/api/analyze",
            files={"file": ("empty.log", b"", "text/plain")},
        )
        self.assertEqual(resp_empty.status_code, 400)
        self.assertIn("empty", resp_empty.json()["detail"].lower())

        # 3. Blank whitespace-only file
        resp_blank = self.client.post(
            "/api/analyze",
            files={"file": ("blank.log", b"   \n\n  \t \n", "text/plain")},
        )
        self.assertEqual(resp_blank.status_code, 400)
        self.assertIn("0 non-blank", resp_blank.json()["detail"].lower())

        # 4. Binary file with null bytes (\x00)
        resp_bin = self.client.post(
            "/api/analyze",
            files={"file": ("binary.log", b"\x7fELF\x02\x01\x01\x00binarypayload", "text/plain")},
        )
        self.assertEqual(resp_bin.status_code, 400)
        self.assertIn("binary", resp_bin.json()["detail"].lower())

        # 5. Non-UTF-8 byte sequence
        resp_utf8 = self.client.post(
            "/api/analyze",
            files={"file": ("bad_utf8.txt", b"2026-03-19 INFO \xff\xfe\xfd invalid utf8\n", "text/plain")},
        )
        self.assertEqual(resp_utf8.status_code, 400)
        self.assertIn("utf-8", resp_utf8.json()["detail"].lower())

        # 6. Oversized file exceeding limit (monkeypatch MAX_UPLOAD_BYTES to 1 KB for fast test)
        with patch("app.main.MAX_UPLOAD_BYTES", 1024):
            resp_large = self.client.post(
                "/api/analyze",
                files={"file": ("huge.log", b"A" * 2048, "text/plain")},
            )
            self.assertEqual(resp_large.status_code, 400)
            self.assertIn("10 mb", resp_large.json()["detail"].lower())

        # 7. Cloud model rejection
        resp_cloud = self.client.post(
            "/api/analyze",
            json={"use_sample": True, "model": "qwen3.5:cloud"},
        )
        self.assertEqual(resp_cloud.status_code, 400)
        self.assertIn("cloud", resp_cloud.json()["detail"].lower())

    # ------------------------------------------------------------------
    # Gate 7: API Contract & Sample Report Schema Validation
    # ------------------------------------------------------------------
    def test_gate7_api_contract_and_sample_report(self) -> None:
        """Verify GET /, GET /api/system, and GET /api/jobs/{job_id} response contracts."""
        # GET / -> HTML UI
        resp_root = self.client.get("/")
        self.assertEqual(resp_root.status_code, 200)
        self.assertIn("text/html", resp_root.headers.get("content-type", ""))
        self.assertIn("Cultive8", resp_root.text)

        # GET /api/system -> telemetry & model list
        resp_sys = self.client.get("/api/system")
        self.assertEqual(resp_sys.status_code, 200)
        sys_data = resp_sys.json()
        self.assertEqual(sys_data["default_model"], DEFAULT_MODEL)
        self.assertEqual(sys_data["token_limit_per_call"], 2048)
        self.assertEqual(sys_data["output_token_budget"], 384)
        self.assertEqual(sys_data["carry_state_budget"], 250)
        self.assertEqual(sys_data["ram_limit_mb"], 4096)
        self.assertTrue(sys_data["sample_log_available"])
        for model_name in sys_data["available_models"]:
            self.assertNotIn("cloud", model_name.lower())

        # GET /api/jobs/phase2-smoke -> full 258-line completed job state
        resp_job = self.client.get("/api/jobs/phase2-smoke")
        self.assertEqual(resp_job.status_code, 200)
        job_data = resp_job.json()
        self.assertEqual(job_data["status"], "completed")
        self.assertEqual(job_data["total_lines"], 258)
        self.assertEqual(job_data["total_chunks"], 11)
        self.assertEqual(job_data["completed_chunks"], 11)
        self.assertTrue(job_data["token_budget"]["strictly_under_2048"])

        report = job_data["report"]
        self.assertIsNotNone(report)
        self.assertEqual(len(report["findings"]), 5)
        self.assertEqual(report["cross_chunk_findings_count"], 4)

        required_finding_keys = {
            "id",
            "attack_type",
            "severity",
            "actor_ip",
            "CrossChunkLinked",
            "chunks_spanned",
            "evidence_lines",
            "evidence_excerpts",
            "reason",
            "suggested_action",
        }
        for finding in report["findings"]:
            self.assertTrue(required_finding_keys.issubset(finding.keys()))
            self.assertGreater(len(finding["evidence_lines"]), 0)
            self.assertEqual(len(finding["evidence_lines"]), len(finding["evidence_excerpts"]))


if __name__ == "__main__":
    unittest.main()
