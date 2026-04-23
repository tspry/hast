# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Project Identity

**HAST — Hardening & Attack Surface Tester**
A web-based security hardening scanner dashboard. The user points it at a target URL, selects a scan profile, and gets a unified findings report. Intended for local/internal use only. No authentication layer by design.

---

## Commands

Everything runs in Docker — no local Python or security tool installation needed.

```bash
./start.sh              # build (first time) + start in foreground, opens browser
./start.sh --build      # force rebuild (use after changing Dockerfile or requirements)
./start.sh --detach     # run in background
./start.sh --logs       # tail logs of running container
./start.sh --down       # stop and remove container

docker compose up --build   # equivalent to ./start.sh --build
docker compose up -d
docker compose logs -f hast
docker compose down
```

Dashboard: `http://localhost:8765`
API base: `http://localhost:8765/api`
WebSocket: `ws://localhost:8765/ws`

---

## Repository Layout

```
HAST/
├── Dockerfile                  # Two-stage: Go tool downloader → Python runtime
├── docker-compose.yml          # Port 8765, cap_add NET_RAW, named volume for hast.db
├── start.sh                    # Docker-only launcher with --build/--detach/--logs/--down flags
├── requirements.txt            # fastapi, uvicorn, aiosqlite, pyyaml, aiofiles, reportlab, httpx
├── config.yaml                 # Runtime config — bind-mounted into container, editable without rebuild
├── README.md
├── backend/
│   ├── main.py                 # FastAPI app entry point, serves frontend/ as static files
│   ├── config.py               # YAML loader, tool path auto-detection, wordlist detection
│   ├── db/
│   │   ├── models.py           # Raw SQL schema strings (CREATE TABLE IF NOT EXISTS)
│   │   └── database.py         # Async aiosqlite CRUD — scans, findings, URLs, checkpoints
│   ├── scanner/
│   │   ├── workflow.py         # Main orchestrator: phases in order, checkpoint/resume, stop flag
│   │   ├── phases/
│   │   │   ├── recon.py        # Phase 1: wafw00f → nmap → whatweb (sequential)
│   │   │   ├── discovery.py    # Phase 2: katana + gospider + hakrawler (parallel) → gau → dedup
│   │   │   ├── scanning.py     # Phase 3: nuclei → ffuf (curl fallback) → JS secret scan loop
│   │   │   └── aggregation.py  # Phase 4: dedup, risk scoring, diff vs prev scan, persist
│   │   └── tools/
│   │       ├── base.py         # ToolRunner + SimpleToolRunner base classes
│   │       ├── wafw00f_tool.py
│   │       ├── nmap_tool.py
│   │       ├── whatweb_tool.py
│   │       ├── crawler_tools.py  # katana, gospider, hakrawler, gau
│   │       ├── nuclei_tool.py
│   │       ├── ffuf_tool.py
│   │       ├── secret_tools.py   # trufflehog, gitleaks, regex SECRET_PATTERNS fallback
│   │       └── curl_tool.py
│   └── api/
│       ├── routes.py           # REST endpoints (see API section below)
│       └── ws_handler.py       # WebSocket handler + ConnectionManager broadcast
└── frontend/
    ├── index.html              # Single HTML page — all UI structure
    ├── css/style.css           # Dark theme, CSS variables, all component styles
    └── js/app.js               # Entire frontend logic — IIFE App singleton, no framework
```

---

## Architecture

### Backend — Python 3.12 / FastAPI / aiosqlite

**Request flow:**
1. Browser opens WebSocket to `/ws`
2. User sends `{type: "start_scan", target, profile}` over WS
3. `ws_handler.py` calls `workflow.start_scan()` which spawns an `asyncio.Task`
4. Workflow runs phases in order; each phase calls `emit(event_type, data)`
5. `emit` → `ConnectionManager.broadcast()` → JSON pushed to all connected WS clients
6. On `scan_complete`, frontend also fetches `/api/scans/{id}/findings` for the final deduped list

**Tool runner pattern** (`tools/base.py`):
- Every tool extends `ToolRunner` or `SimpleToolRunner`
- `_run_subprocess()` uses `asyncio.create_subprocess_exec` and streams stdout/stderr line by line as `ToolEvent` objects
- Missing tool binary → `_unavailable_event()` (stream="warning") → phase skips it and continues
- Tool detection: `config.resolve_tool_path(name)` checks `config.yaml tool_paths` override first, then `shutil.which()`

**Finding schema** (SQLite + WebSocket payload + export):
```python
{
  "id":          str,   # UUID
  "scan_id":     str,   # UUID
  "tool":        str,   # "nuclei" | "ffuf" | "nmap" | "wafw00f" | "whatweb" | "curl" |
                        # "gitleaks" | "trufflehog" | "regex-secret-scan"
  "severity":    str,   # "critical" | "high" | "medium" | "low" | "info"
  "name":        str,
  "url":         str,
  "evidence":    str,
  "remediation": str,
  "cvss_score":  float | None,
  "risk_score":  int,   # 0–100, computed in aggregation.py
  "timestamp":   str,   # ISO 8601
  "is_new":      bool,  # True if not seen in previous scan for same target
}
```

**WebSocket event types** (server → client):

| type | payload |
|---|---|
| `scan_queued` | `{scan_id, target, profile}` |
| `scan_started` | `{scan_id, target, profile}` |
| `phase_update` | `{phase, status, data?}` — status: running/completed/failed |
| `tool_status` | `{tool, status, message?}` — status: queued/running/done/skipped/failed |
| `log` | `{tool, stream, data}` — stream: stdout/stderr/info/warning/error |
| `finding` | `{finding: Finding}` |
| `waf_detected` | `{detected: bool, name: str, message: str}` |
| `scan_complete` | `{scan_id, stats, findings[]}` |
| `scan_stopped` | `{scan_id, message}` |
| `scan_error` | `{error: str}` |

**WebSocket event types** (client → server):

| type | payload |
|---|---|
| `start_scan` | `{target, profile, resume?, scan_id?}` |
| `stop_scan` | `{scan_id}` |
| `ping` | — |

**Scan profiles:**
- `quick` — recon only + nuclei exposures + ffuf priority paths. No crawl phase.
- `standard` — full workflow, katana + gau, moderate rate limits
- `deep` — all crawlers, headless nuclei, full ffuf wordlist, lowest rate limits

**Resume:** Each phase writes a checkpoint to `scan_checkpoints` table on completion. Passing `resume=True` + existing `scan_id` skips already-completed phases and reloads their data from DB.

**Rate limiting:** `config.get_rate_limit_ms(waf_detected)` — returns `rate_limit_ms` normally, `waf_rate_limit_ms` if WAF was detected. Each tool converts ms → req/s as needed.

### Frontend — Vanilla JS, no build step

Single `App` IIFE in `frontend/js/app.js`. No framework, no bundler. FastAPI serves `frontend/` as static files.

Key functions:
- `connect()` — WebSocket connect with auto-reconnect (3s)
- `handleMessage(msg)` — central dispatcher for all WS event types
- `onFinding(f)` — pushes to `allFindings[]`, calls `updateCounts()` + `applyFilters()`
- `applyFilters()` — re-renders findings table from `allFindings[]` applying keyword/severity/tool filters
- `renderFindings()` — builds `<tr>` HTML, handles expanded row state via `expandedRows` Set
- `updatePhase(phase, status)` / `updateToolStatus(tool, status)` — update left panel dots and badges
- `loadHistoryScan(scanId)` — loads a past scan from REST API into the UI without running a new scan
- `exportData(format)` — opens `/api/scans/{id}/export/{format}` in new tab

Dark theme uses CSS custom properties (all in `style.css` `:root`). Severity colors: `--sev-critical #ff4d4d`, `--sev-high #f97316`, `--sev-medium #eab308`, `--sev-low #3b82f6`, `--sev-info #6b7280`.

### Database — SQLite via aiosqlite

Tables: `scans`, `findings`, `discovered_urls`, `scan_checkpoints`
Schema defined as raw SQL strings in `db/models.py` → executed with `executescript` on startup.
DB path: `/data/hast.db` inside container (named Docker volume), overridable via `HAST_DB_PATH` env var.

### REST API endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/scans` | List scan history (limit=50) |
| GET | `/api/scans/{id}` | Get single scan record |
| POST | `/api/scans/{id}/stop` | Stop a running scan |
| GET | `/api/scans/{id}/findings` | Get findings (supports ?severity=, ?tool=, ?keyword=) |
| GET | `/api/scans/{id}/diff` | Diff vs previous scan on same target |
| GET | `/api/scans/{id}/export/json` | Export full scan as JSON |
| GET | `/api/scans/{id}/export/csv` | Export findings as CSV |
| GET | `/api/scans/{id}/export/pdf` | Export PDF report (reportlab) |
| GET | `/api/config` | Read current config |
| POST | `/api/config` | Update config (persists to config.yaml) |
| GET | `/api/tools/status` | Availability check for all 12 tools |
| POST | `/api/bulk-scan` | Queue sequential scans for multiple targets `{targets[], profile}` |
| GET | `/api/bulk-scan/summary` | Latest scan result per target `?targets=a.com,b.com` |

---

## Docker

**Two-stage Dockerfile:**
- Stage 1 (`tool-downloader`): debian + curl, downloads latest GitHub release binaries for nuclei, katana, gospider, hakrawler, gau, ffuf, trufflehog, gitleaks. Each download is `|| true` — failures are warnings, not errors.
- Stage 2 (final): python:3.12-slim + apt (nmap, curl, ruby) + gem (whatweb) + pip (wafw00f). Copies binaries from stage 1 via a shell loop that only installs present files.

**Key docker-compose settings:**
- `cap_add: [NET_RAW, NET_ADMIN]` — nmap needs raw socket access for SYN scanning
- `config.yaml` bind-mounted — edit settings without rebuilding
- Named volume `hast-data` mounted at `/data` — SQLite DB persists across restarts/rebuilds
- `server_host: 0.0.0.0` and `open_browser: false` patched into config at image build time

---

## config.yaml Reference

| Key | Default | Notes |
|---|---|---|
| `nuclei_templates_path` | `""` (auto) | Auto-detects `$NUCLEI_TEMPLATES` → `~/.local/nuclei-templates` → `~/nuclei-templates` |
| `seclists_path` | `""` (auto) | Auto-detects `/usr/share/seclists` → `~/seclists` |
| `default_profile` | `standard` | |
| `rate_limit_ms` | `150` | Normal request delay |
| `waf_rate_limit_ms` | `500` | Request delay when WAF detected |
| `respect_robots` | `true` | |
| `tool_paths` | `{}` | Per-tool binary path overrides, e.g. `nuclei: /opt/bin/nuclei` |
| `user_agents` | list of 4 | Cycled per-request |
| `server_host` | `127.0.0.1` | Set to `0.0.0.0` automatically inside container |
| `server_port` | `8765` | |
| `open_browser` | `true` | Set to `false` automatically inside container |

---

## Known Gaps / Future Work

These areas are incomplete or not yet implemented — a future session should pick up from here:

- **`PRIORITY_PATHS` in `ffuf_tool.py`** is the master list of probed paths — add new paths there. The list is grouped by stack (.NET, PHP/Laravel/WP/Symfony/Drupal/Joomla/CI, Node/React/Vue/Angular/Next/Nuxt, Python/Django/Flask, Rails, Java/Spring, Go, DevOps, Git, Logs, Backups, API docs, SSH/certs, Cloud creds). `REMEDIATION_FOR` and the `_CRITICAL/_HIGH/_MEDIUM` tier lists must be kept in sync when adding new paths.
- **`/api/probe-paths/count`** returns `len(PRIORITY_PATHS)` — shown in the Bulk Scan modal.
- **Config tab does not expose `tool_paths`** — individual tool binary overrides require editing `config.yaml` directly
- **Config tab does not expose `user_agents`** — same, file-only for now
- **`trufflehog` integration is partial** — `scanning.py` imports it but the URL-based scanning mode is not fully wired; regex fallback + gitleaks handle JS scanning in practice
- **Scan resume UI** — the backend supports `resume=True` + `scan_id` but there is no button in the UI to resume an interrupted scan (History tab loads past scans read-only; it does not re-run them)
- **No per-finding false-positive marking** — findings cannot be dismissed or marked as accepted risk in the UI
- **nuclei `--headless` flag** in deep profile requires Chromium inside the container — not currently installed; headless mode will fall back gracefully but JS-rendered targets won't be fully covered
- **`robots.txt` toggle** — `respect_robots` is in config but no tool currently reads it; needs to be passed to katana (`-cf robots`) and ffuf
- **`wafw00f` JSON output parsing** — the tool's `--format json` flag behavior varies by version; the current parser also falls back to regex on plain-text output. Verify against installed version.
- **PDF export caps at 200 findings** — hardcoded in `routes.py:_generate_pdf()`; increase if needed
- **No HTTPS** — dashboard is HTTP only; fine for localhost, add a reverse proxy (nginx/caddy) if exposing on LAN

---

## Patterns to Follow When Adding Features

**Adding a new tool:**
1. Create `backend/scanner/tools/<toolname>_tool.py` extending `SimpleToolRunner`
2. Set `name` and `binary` class attributes
3. Parse output into `Finding` objects, yield them alongside `ToolEvent` log lines
4. Import and call it from the appropriate phase in `backend/scanner/phases/`
5. Add a `<div class="tool-row" id="tool-<name>">` row to the correct phase section in `frontend/index.html`

**Adding a new REST endpoint:**
- Add to `backend/api/routes.py` under the existing `router`
- No registration needed — router is included in `main.py` with `app.include_router(router)`

**Adding a new WebSocket event type:**
- Server side: call `await emit("your_event_type", {...})` from any phase or workflow function
- Client side: add a `case "your_event_type":` block in `handleMessage()` in `frontend/js/app.js`

**Adding a new Config tab field:**
- Add `<input>` to the config form in `index.html`
- Read/write it in `loadConfig()` / `saveConfig()` in `app.js`
- Add the key to the `allowed_keys` set in `routes.py:update_config()`
- Add it to `config.py:load_config()` with a sensible default
