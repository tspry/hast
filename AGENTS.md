# HAST Agent Guide

HAST is a Docker-first security scanning dashboard. Start with [README.md](README.md) for product and workflow context, and [CLAUDE.md](CLAUDE.md) for the current architecture map and commands.

## Working Rules

- Treat Docker as the only supported runtime; use `./start.sh` or `docker compose` instead of local Python tooling.
- Keep changes minimal and consistent with the existing split: FastAPI backend in `backend/`, single-page vanilla frontend in `frontend/`, and tool wrappers in `backend/scanner/tools/`.
- Prefer updating existing docs over duplicating them here. Link to [README.md](README.md) or [CLAUDE.md](CLAUDE.md) when a detail is already documented.
- Do not assume missing security tools are fatal. Tool wrappers are designed to warn and continue when a binary is unavailable.
- Preserve the WebSocket-first flow. Live scan state is pushed over `/ws`; REST is mainly for history, export, config, and bulk actions.

## Codebase Conventions

- Backend startup lives in [backend/main.py](backend/main.py); config loading and runtime defaults come from [backend/config.py](backend/config.py).
- REST endpoints are added in [backend/api/routes.py](backend/api/routes.py); WebSocket handling lives in [backend/api/ws_handler.py](backend/api/ws_handler.py).
- Scan orchestration is phase-based in [backend/scanner/workflow.py](backend/scanner/workflow.py) and `backend/scanner/phases/`.
- Tool adapters should extend the existing runner patterns in [backend/scanner/tools/base.py](backend/scanner/tools/base.py) and emit both log events and findings.
- The frontend is a single vanilla JS app in [frontend/js/app.js](frontend/js/app.js); avoid introducing a build step unless the project direction changes.

## Repo-Specific Pitfalls

- Keep `config.yaml` bind-mount friendly. Runtime config is meant to be edited without rebuilding the image.
- Missing binaries should degrade gracefully, not block a scan.
- The UI state is ephemeral; the database is the source of truth for scan history and exports.
- If you need stack-specific paths or scan coverage details, check `backend/scanner/tools/ffuf_tool.py` and the existing nuclei templates under `nuclei-templates/hast/` instead of rewriting the lists here.

## Before Changing Things

- Read the relevant phase or tool file before editing it.
- Check whether the behavior is already documented in [README.md](README.md) or [CLAUDE.md](CLAUDE.md).
- Keep any new guidance concise, actionable, and linked to source files rather than copied into this file.