<!-- agent-harness context index -->
# Project context

Project: /home/ahnaf-zakaria/Desktop/Cultive8
Identity: 55534326-de29-4630-acc4-afd0b6ecafb0

- log-analyzer: Master architecture and context-switching index for the Cultive8 Local AI Security Log Analyzer using qwen3.5:0.8b. — revision 4; next: Start phase-1-core in a fresh chat using harness context resume /home/ahnaf-zakaria/Desktop/Cultive8 --task phase-1-core
  Packet: /home/ahnaf-zakaria/.local/share/agent-harness/projects/55534326-de29-4630-acc4-afd0b6ecafb0/tasks/log-analyzer.json
- phase-1-core: Phase 1: Set up .venv and qwen3.5:0.8b, and implement app/tokenizer.py and app/chunker.py under the 2,048-token budget. — revision 2; next: Phase 1 complete. Switch to task phase-2-llm in a fresh chat.
  Packet: /home/ahnaf-zakaria/.local/share/agent-harness/projects/55534326-de29-4630-acc4-afd0b6ecafb0/tasks/phase-1-core.json
- phase-2-llm: Phase 2: Implement sequential local LLM analyzer (app/analyzer.py) with ActorLedger and cross-chunk report merger (app/merger.py). — revision 2; next: Proceed to phase-3-web: read ONLY .harness/design/03-backend-api-and-sse/SPEC.md, .harness/design/04-frontend-ui-contract/SPEC.md, app/analyzer.py, and app/merger.py to implement app/main.py and app/static/index.html.
  Packet: /home/ahnaf-zakaria/.local/share/agent-harness/projects/55534326-de29-4630-acc4-afd0b6ecafb0/tasks/phase-2-llm.json
- phase-3-web: Phase 3: Implement FastAPI backend (app/main.py) and Drunk-Man-Usable single-page operational UI (app/static/index.html). — revision 2; next: Execute phase-4-verify: implement tests/test_analyzer.py, README.md, and sample_output/Cultive8_Sample_Analysis_Report.json, run pytest + live verification.
  Packet: /home/ahnaf-zakaria/.local/share/agent-harness/projects/55534326-de29-4630-acc4-afd0b6ecafb0/tasks/phase-3-web.json
- phase-4-verify: Phase 4: Verify all 7 gates via pytest, generate sample_output/Cultive8_Sample_Analysis_Report.json, write README.md and AI_USAGE.md, verify live UI in browser, and commit deliverables. — revision 3; next: All phases complete and verified; ready for submission.
  Packet: /home/ahnaf-zakaria/.local/share/agent-harness/projects/55534326-de29-4630-acc4-afd0b6ecafb0/tasks/phase-4-verify.json
