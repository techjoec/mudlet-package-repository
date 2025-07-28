# Agent Instructions

- This repository contains scripts to manage and scan Mudlet packages.
- Use `scan_packages.py` to analyze packages in the `packages/` directory for risky Lua patterns. The scanner is organized around `dataclasses` for pattern definitions and results.
- The scan processes all packages and produces `scan_report.html` with columns: package, file, line number, category, matched text, address, and context.
- Ignore the `MudletBusted.mpackage` file when scanning packages.
- Do not mark packages as scanned; this repository is currently in testing.
- When adding or modifying detection logic or hints, update this `AGENTS.md` and regenerate `scan_report.html`.
- The scanner strips Lua comments before matching to avoid false positives from commented-out code.
- Detection logic skips lines that define functions such as `openUrl = function(...)` to avoid false positives.
- Network detection now matches `require('socket.http')`, `socket.http.request` and similar calls rather than any URL string. It also checks for Mudlet helper functions like `getHTTP`, `postHTTP`, `putHTTP`, `deleteHTTP`, `customHTTP`, `openWebPage`, `openUrl`, `downloadFile`, `installPackage`, `uninstallPackage`, and `unzipAsync`.
- See [docs/suspicious-functions.md](docs/suspicious-functions.md) for a summary of these functions and why they are flagged.
- Literal URLs and IP addresses are flagged unless they appear in package `description` blocks.
- FQDNs are checked via DNS lookups; unresolved domains are flagged as `Unregistered` and domains on known public hosting providers are marked as `Publicly Writable`.
