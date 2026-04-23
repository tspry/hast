"""Tests for backend/api/ws_handler.py — ConnectionManager and WebSocket handling."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from backend.api.ws_handler import ConnectionManager


# ---------------------------------------------------------------------------
# ConnectionManager
# ---------------------------------------------------------------------------

class TestConnectionManager:
    def _make_ws(self) -> AsyncMock:
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_text = AsyncMock()
        return ws

    @pytest.mark.asyncio
    async def test_connect_global(self):
        mgr = ConnectionManager()
        ws = self._make_ws()
        await mgr.connect(ws)
        ws.accept.assert_called_once()
        assert ws in mgr._global

    @pytest.mark.asyncio
    async def test_connect_with_scan_id(self):
        mgr = ConnectionManager()
        ws = self._make_ws()
        await mgr.connect(ws, scan_id="scan-1")
        ws.accept.assert_called_once()
        assert ws in mgr._connections.get("scan-1", [])

    def test_disconnect_global(self):
        mgr = ConnectionManager()
        ws = self._make_ws()
        mgr._global.append(ws)
        mgr.disconnect(ws)
        assert ws not in mgr._global

    def test_disconnect_by_scan_id(self):
        mgr = ConnectionManager()
        ws = self._make_ws()
        mgr._connections["scan-1"] = [ws]
        mgr.disconnect(ws, scan_id="scan-1")
        assert ws not in mgr._connections["scan-1"]

    def test_disconnect_unknown_ws_noop(self):
        mgr = ConnectionManager()
        ws = self._make_ws()
        # Should not raise even if not registered
        mgr.disconnect(ws)
        mgr.disconnect(ws, scan_id="scan-1")

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_global_clients(self):
        mgr = ConnectionManager()
        ws = self._make_ws()
        mgr._global.append(ws)

        await mgr.broadcast({"type": "ping"})
        ws.send_text.assert_called_once_with(json.dumps({"type": "ping"}))

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_scan_specific_clients(self):
        mgr = ConnectionManager()
        ws_global = self._make_ws()
        ws_scan = self._make_ws()
        mgr._global.append(ws_global)
        mgr._connections["scan-1"] = [ws_scan]

        await mgr.broadcast({"type": "update"}, scan_id="scan-1")
        # Both global and scan-specific should receive the message
        ws_global.send_text.assert_called_once()
        ws_scan.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_removes_dead_connections(self):
        mgr = ConnectionManager()
        ws = self._make_ws()
        ws.send_text.side_effect = Exception("Connection closed")
        mgr._global.append(ws)

        await mgr.broadcast({"type": "test"})
        # Dead connection should be removed
        assert ws not in mgr._global

    @pytest.mark.asyncio
    async def test_broadcast_multiple_clients(self):
        mgr = ConnectionManager()
        ws1 = self._make_ws()
        ws2 = self._make_ws()
        mgr._global.extend([ws1, ws2])

        await mgr.broadcast({"type": "event", "data": "hello"})
        ws1.send_text.assert_called_once()
        ws2.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_json_serialised(self):
        mgr = ConnectionManager()
        ws = self._make_ws()
        mgr._global.append(ws)

        msg = {"type": "log", "data": {"tool": "nmap", "stream": "stdout", "data": "scanning"}}
        await mgr.broadcast(msg)
        call_arg = ws.send_text.call_args[0][0]
        parsed = json.loads(call_arg)
        assert parsed == msg


# ---------------------------------------------------------------------------
# WebSocket message handling (via handle_websocket)
# ---------------------------------------------------------------------------

class TestHandleWebsocket:
    """
    These tests exercise the handle_websocket dispatch logic by simulating
    the WebSocket receive/send cycle with mock objects.
    """

    def _make_ws(self, messages: list[str]) -> AsyncMock:
        """Return a mock WebSocket that serves provided messages then disconnects."""
        from fastapi import WebSocketDisconnect
        ws = AsyncMock()
        ws.accept = AsyncMock()
        responses = [m for m in messages]

        call_count = 0

        async def _receive_text():
            nonlocal call_count
            if call_count < len(responses):
                result = responses[call_count]
                call_count += 1
                return result
            raise WebSocketDisconnect()

        ws.receive_text = _receive_text
        ws.send_text = AsyncMock()
        return ws

    @pytest.mark.asyncio
    async def test_ping_receives_pong(self, db):
        from backend.api.ws_handler import handle_websocket
        ws = self._make_ws([json.dumps({"type": "ping"})])
        await handle_websocket(ws)

        sent_payloads = [json.loads(call[0][0]) for call in ws.send_text.call_args_list]
        assert any(p.get("type") == "pong" for p in sent_payloads)

    @pytest.mark.asyncio
    async def test_invalid_json_returns_error(self, db):
        from backend.api.ws_handler import handle_websocket
        ws = self._make_ws(["not valid json"])
        await handle_websocket(ws)

        sent_payloads = [json.loads(c[0][0]) for c in ws.send_text.call_args_list]
        assert any(p.get("type") == "error" for p in sent_payloads)

    @pytest.mark.asyncio
    async def test_unknown_message_type_returns_error(self, db):
        from backend.api.ws_handler import handle_websocket
        ws = self._make_ws([json.dumps({"type": "unknown_type_xyz"})])
        await handle_websocket(ws)

        sent_payloads = [json.loads(c[0][0]) for c in ws.send_text.call_args_list]
        assert any(p.get("type") == "error" for p in sent_payloads)

    @pytest.mark.asyncio
    async def test_start_scan_empty_target_returns_error(self, db):
        from backend.api.ws_handler import handle_websocket
        ws = self._make_ws([json.dumps({"type": "start_scan", "target": ""})])
        await handle_websocket(ws)

        sent_payloads = [json.loads(c[0][0]) for c in ws.send_text.call_args_list]
        assert any(p.get("type") == "error" for p in sent_payloads)

    @pytest.mark.asyncio
    async def test_start_scan_invalid_scheme_returns_error(self, db):
        from backend.api.ws_handler import handle_websocket
        # A URL that already starts with https:// but has no netloc triggers validation error
        ws = self._make_ws([json.dumps({
            "type": "start_scan",
            "target": "https://",
            "profile": "quick",
        })])
        await handle_websocket(ws)

        sent_payloads = [json.loads(c[0][0]) for c in ws.send_text.call_args_list]
        assert any(p.get("type") == "error" for p in sent_payloads)

    @pytest.mark.asyncio
    async def test_start_scan_normalises_missing_scheme(self, db):
        """A target without http:// should be prefixed with https://."""
        from backend.api.ws_handler import handle_websocket
        with patch("backend.api.ws_handler.start_scan",
                   new_callable=AsyncMock, return_value="fake-scan-id"):
            ws = self._make_ws([json.dumps({
                "type": "start_scan",
                "target": "example.com",
                "profile": "quick",
            })])
            await handle_websocket(ws)

        sent_payloads = [json.loads(c[0][0]) for c in ws.send_text.call_args_list]
        queued = next((p for p in sent_payloads if p.get("type") == "scan_queued"), None)
        assert queued is not None
        assert queued["data"]["target"].startswith("https://")

    @pytest.mark.asyncio
    async def test_stop_scan_sends_ack(self, db):
        from backend.api.ws_handler import handle_websocket
        with patch("backend.api.ws_handler.stop_scan",
                   new_callable=AsyncMock, return_value=True):
            ws = self._make_ws([json.dumps({
                "type": "stop_scan",
                "scan_id": "some-scan-id",
            })])
            await handle_websocket(ws)

        sent_payloads = [json.loads(c[0][0]) for c in ws.send_text.call_args_list]
        ack = next((p for p in sent_payloads if p.get("type") == "stop_ack"), None)
        assert ack is not None
        assert ack["data"]["stopped"] is True
