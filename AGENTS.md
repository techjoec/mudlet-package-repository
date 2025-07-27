# Agent Instructions

- This repository contains scripts to manage and scan Mudlet packages.
- Use `scan_packages.py` to analyze packages in the `packages/` directory for risky Lua patterns.
- The scan should stop after 10 matches and produce `scan_report.csv` with columns: package, file, line number, category, matched text, and context.
- Do not mark packages as scanned; this repository is currently in testing.
- When adding or modifying detection logic or hints, update this `AGENTS.md` and regenerate `scan_report.csv`.
- The scanner strips Lua comments before matching to avoid false positives from commented-out code.
- Detection also covers Mudlet networking helpers like `openUrl()` and `downloadFile()`.
