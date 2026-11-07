# 04 — Frontend Visual & Interaction Contract ("Drunk-Man Usable" Operational UI)

- **Purpose**: Selected visual contract for `app/static/index.html` using `.agents/skills/ui-ux-design` (`styles.md`: Product / operational + Minimalist / Swiss; `decisions.md`: D02, D03, D04, D05, D08, D09, D13; `anti-generic.md`: unslop check).
- **Scope**: Phase 3 (`phase-3-web`).
- **Update Policy**: Update only if UI states or visual tokens change.
- **Loading Budget**: ~950 tokens.

## 1. Organizing Concept & "Drunk-Man Usable" Rule

- **Audience & Primary Task**: A tired security reviewer or grader uploading a `.log`/`.txt` file, watching chunk-by-chunk local model progress under the 2,048-token cap, and reading the unified incident report.
- **Drunk-Man Usable Principle (D05 + D09)**:
  - **One screen, one vertical flow, zero hidden menus, zero tabs required to finish the task.**
  - At load time, there is only ONE decision box: **"1. Choose Log File & Run Local AI Analysis"** with two giant, unmistakable buttons:
    - Primary CTA: **`Upload .log / .txt & Analyze`** (opens file picker or accepts drag-and-drop anywhere on the box).
    - Instant Demo CTA: **`Analyze Supplied Cultive8 Server Log`** (1 click, zero file-hunting needed during demo/grading).
  - While running, the progress box updates live every second with big numerals: **`Part 6 of 15`** + exact lines (`L91–L108`) + exact token meter (`1,342 / 2,048 tokens`) + findings saved so far.
  - When done (and partially while running), findings appear immediately below in severity order (`CRITICAL` -> `HIGH` -> `MEDIUM` -> `LOW`) with clickable line badges (`L5`, `L196`, `L201`) and plain-English **"What happened"** and **"What to do now"**.

## 2. Anti-Generic ("Unslop") Rules Applied (`references/taste/anti-generic.md`)

- **NO AI-slop tropes**: No dark-mode purple/cyan neon gradients, no glassmorphism blur cards, no fake radar charts, no marketing hero slogan, no decorative animations.
- **Constraint-authored grammar (D13)**: The 2,048-token call cap and 4 GB RAM cap are real operational constraints; they are surfaced honestly as a compact top ledger strip (`Model: qwen3.5:0.8b · Context Cap: 2,048 tok/call · Backend RAM: 52 MB / 4,096 MB`).

## 3. Typography & Color Tokens (D02, D04 — WCAG 2.2 AA Checked)

- **Typography**:
  - UI & Reading Copy: `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif` (`16px` base, `1.5` line-height, max `72ch` prose width).
  - Evidence Lines, IPs, Paths, Token Meters: `"JetBrains Mono", "SFMono-Regular", Consolas, monospace` (`13.5px`, `font-variant-numeric: tabular-nums`).
  - Scale: Page Title `24px/700`, Section Header `18px/700`, Finding Title `17px/700`, Body `15px/400`, Meta/Badges `13px/600`.
- **Daylight Operational Ledger Palette**:
  - Canvas Background: `#F5F4EF` (warm stone paper, zero glare)
  - Card Surface: `#FFFFFF` with `1px solid #D6D3C9` crisp border (`border-radius: 6px`)
  - Primary Ink: `#141413` (contrast `16.4:1` on white)
  - Secondary Ink: `#4A4944` (contrast `7.8:1` on white)
  - Primary Action Button: `#14532D` (deep forest green) with `#FFFFFF` text (`8.9:1`), hover `#0F3F22`, focus ring `3px solid #1D4ED8` (`offset 2px`)
  - Severity Roles (Color + Text Label + Border weight — never color alone):
    - `CRITICAL`: bg `#FEF2F2`, border `2px solid #B91C1C`, badge bg `#B91C1C`, badge text `#FFFFFF`
    - `HIGH`: bg `#FFF7ED`, border `2px solid #C2410C`, badge bg `#C2410C`, badge text `#FFFFFF`
    - `MEDIUM`: bg `#FEFCE8`, border `1.5px solid #A16207`, badge bg `#A16207`, badge text `#FFFFFF`
    - `LOW`: bg `#F8FAFC`, border `1.5px solid #334155`, badge bg `#334155`, badge text `#FFFFFF`

## 4. Complete Interaction States & Responsive Rules (D08, D09, D10)

1. **Idle State**: Clear upload card + 1-click supplied log button + model selector dropdown (`qwen3.5:0.8b` selected).
2. **Invalid Upload State**: Inline high-contrast error banner (`role="alert"`) explaining why the file was rejected (e.g., *"Only .log and .txt text files are accepted"*) without clearing previous valid results.
3. **Running / Streaming Progress State**:
   - Action buttons disabled with `aria-busy="true"` to prevent duplicate jobs.
   - Progress bar + tabular chunk log table showing `Part #`, `Lines`, `Prompt Tokens`, `Output Tokens`, `Total / 2,048`, `Time`, `Status`.
   - Live partial findings list so the user sees findings accumulate before the last chunk finishes.
4. **Completed Report State**:
   - Executive Summary banner with key counts (Confirmed Findings, Cross-Part Linked Chains, Operational Errors Ignored, Max Token Call Used).
   - Finding Cards with: Severity, Attack Type, Actor IP/Username, Cross-Part Badge (`Linked across Parts 1..12`), Evidence Line pills (`L5`, `L196`, `L201`) + collapsible/visible exact log excerpts, Short Reason, and Suggested Action.
   - Collapsible **Chunk Token Audit Table** & **Ignored Operational Noise / Prompt-Injection Quarantine Ledger**.
5. **Responsive**: Single-column stack at `320px/390px/768px/1440px`; tables scroll horizontally inside a bordered container without breaking page width; respects `prefers-reduced-motion: reduce`.
