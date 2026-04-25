"""HAST – Security Hardening Scanner Dashboard
Main FastAPI application entry point.
"""

from __future__ import annotations

import asyncio
import os
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend.api.ws_handler import handle_websocket
from backend.config import get_config, load_config
from backend.db.database import init_db

# ── Lifespan (replaces deprecated @app.on_event) ──────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    load_config()
    await init_db()
    cfg = get_config()
    print("\n  HAST Security Scanner")
    print("  ─────────────────────────────────────")
    print(f"  Dashboard: http://{cfg['server_host']}:{cfg['server_port']}")
    print(f"  API:       http://{cfg['server_host']}:{cfg['server_port']}/api")
    print("  ─────────────────────────────────────\n")

    if cfg.get("open_browser", True):
        asyncio.get_event_loop().call_later(
            1.5,
            lambda: webbrowser.open(
                f"http://{cfg['server_host']}:{cfg['server_port']}"
            ),
        )

    yield

    # Shutdown
    from backend.db.database import close_db

    await close_db()


# ── App setup ─────────────────────────────────────────────────────────────────


def _build_cors_origins() -> list[str]:
    defaults = [
        "http://localhost:8765",
        "http://127.0.0.1:8765",
        "http://0.0.0.0:8765",
    ]
    # HAST_ALLOWED_ORIGINS env var takes priority (comma-separated)
    # e.g. -e HAST_ALLOWED_ORIGINS=https://hast.internal.company.com
    env_origins = os.environ.get("HAST_ALLOWED_ORIGINS", "")
    if env_origins:
        extra = [o.strip().rstrip("/") for o in env_origins.split(",") if o.strip()]
    else:
        extra = get_config().get("allowed_origins", [])
        if isinstance(extra, str):
            extra = [extra]
        extra = [o.rstrip("/") for o in extra if o]
    return defaults + extra


app = FastAPI(title="HAST Security Scanner", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_build_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
FRONTEND_ROOT = FRONTEND_DIR.resolve()


# ── Routes ────────────────────────────────────────────────────────────────────

app.include_router(router)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await handle_websocket(ws)


# ── Static files ──────────────────────────────────────────────────────────────

if FRONTEND_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR)), name="frontend")

    @app.get("/")
    async def serve_index():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    @app.get("/{path:path}")
    async def serve_static(path: str):
        target = (FRONTEND_DIR / path).resolve()
        try:
            target.relative_to(FRONTEND_ROOT)
        except ValueError:
            return FileResponse(str(FRONTEND_DIR / "index.html"))
        if target.is_file():
            return FileResponse(str(target))
        return FileResponse(str(FRONTEND_DIR / "index.html"))


# ── Entry point ───────────────────────────────────────────────────────────────


def main():
    load_config()
    cfg = get_config()
    uvicorn.run(
        "backend.main:app",
        host=cfg.get("server_host", "127.0.0.1"),
        port=int(cfg.get("server_port", 8765)),
        reload=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
