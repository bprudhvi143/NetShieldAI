import asyncio
from typing import List, Dict, Any, Optional
from fastapi import WebSocket, status
import logging

logger = logging.getLogger("app.websocket_manager")

class ConnectionManager:
    """
    Thread-safe WebSocket Connection Manager.
    Allows async WebSocket clients to subscribe and receives broadcasts
    from background processing threads using asyncio.run_coroutine_threadsafe.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    def set_event_loop(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"New WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def _send_json_safe(self, websocket: WebSocket, message: dict):
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.debug(f"Failed to send websocket message (client likely disconnected): {e}")
            # Schedule disconnection of this stale socket
            self.disconnect(websocket)

    async def broadcast_async(self, message: dict):
        """Async broadcast (to be called inside the event loop)."""
        if not self.active_connections:
            return
        # Create send tasks for all active connections
        tasks = [self._send_json_safe(ws, message) for ws in list(self.active_connections)]
        await asyncio.gather(*tasks, return_exceptions=True)

    def broadcast(self, message: dict):
        """
        Thread-safe synchronous broadcast.
        Safe to call from background worker threads.
        """
        if not self.active_connections:
            return
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast_async(message), self.loop)
        else:
            logger.warning("Event loop is not running. WebSocket broadcast skipped.")

# Global singleton instance
websocket_manager = ConnectionManager()
