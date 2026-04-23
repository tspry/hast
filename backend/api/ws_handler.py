"""WebSocket handler – real-time scan streaming."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from backend.scanner.workflow import start_scan, stop_scan


class ConnectionManager:
    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}  # scan_id -> [ws]
        self._global: list[WebSocket] = []

    async def connect(self, ws: WebSocket, scan_id: str = None):
        await ws.accept()
        if scan_id:
            self._connections.setdefault(scan_id, []).append(ws)
        else:
            self._global.append(ws)

    def disconnect(self, ws: WebSocket, scan_id: str = None):
        if scan_id and scan_id in self._connections:
            self._connections[scan_id] = [c for c in self._connections[scan_id] if c != ws]
        self._global = [c for c in self._global if c != ws]

    async def broadcast(self, msg: dict, scan_id: str = None):
        """Send message to all clients watching this scan (or all global clients)."""
        text = json.dumps(msg)
        targets = list(self._global)
        if scan_id and scan_id in self._connections:
            targets += self._connections[scan_id]

        dead = []
        for ws in targets:
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


async def handle_websocket(ws: WebSocket):
    """Main WebSocket handler."""
    await manager.connect(ws)
    current_scan_id = None

    async def emit(event_type: str, data: Any):
        msg = {"type": event_type, "data": data}
        await manager.broadcast(msg, scan_id=current_scan_id)

    try:
        while True:
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                # Send ping to keep alive
                try:
                    await ws.send_text(json.dumps({"type": "ping"}))
                except Exception:
                    break
                continue

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_text(json.dumps({
                    "type": "error", "data": {"message": "Invalid JSON"}
                }))
                continue

            msg_type = msg.get("type")

            if msg_type == "start_scan":
                target = msg.get("target", "").strip()
                profile = msg.get("profile", "standard").strip()
                resume = msg.get("resume", False)
                resume_id = msg.get("scan_id")

                if not target:
                    await ws.send_text(json.dumps({
                        "type": "error", "data": {"message": "target is required"}
                    }))
                    continue

                # Normalize target
                if not target.startswith(("http://", "https://")):
                    target = "https://" + target

                # Basic URL validation — reject non-http schemes and bare IPs
                from urllib.parse import urlparse
                parsed = urlparse(target)
                if parsed.scheme not in ("http", "https") or not parsed.netloc:
                    await ws.send_text(json.dumps({
                        "type": "error",
                        "data": {"message": "Invalid target URL"}
                    }))
                    continue

                current_scan_id = await start_scan(
                    target=target,
                    profile=profile,
                    emit=emit,
                    scan_id=resume_id if resume else None,
                    resume=resume,
                )
                await ws.send_text(json.dumps({
                    "type": "scan_queued",
                    "data": {"scan_id": current_scan_id, "target": target, "profile": profile}
                }))

            elif msg_type == "stop_scan":
                scan_id = msg.get("scan_id") or current_scan_id
                if scan_id:
                    stopped = await stop_scan(scan_id)
                    await ws.send_text(json.dumps({
                        "type": "stop_ack",
                        "data": {"scan_id": scan_id, "stopped": stopped}
                    }))

            elif msg_type == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))

            else:
                await ws.send_text(json.dumps({
                    "type": "error",
                    "data": {"message": f"Unknown message type: {msg_type}"}
                }))

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await ws.send_text(json.dumps({
                "type": "error", "data": {"message": str(exc)}
            }))
        except Exception:
            pass
    finally:
        manager.disconnect(ws, current_scan_id)
