# websocket_listener.py (put this in utils/ or same dir)

from PyQt6.QtCore import QThread, pyqtSignal
import asyncio
import websockets
import json

class WebSocketListener(QThread):
    message_received = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._running = True

    def run(self):
        asyncio.run(self.listen())

    async def listen(self):
        try:
            async with websockets.connect("ws://localhost:8765") as websocket:
                while self._running:
                    msg = await websocket.recv()
                    try:
                        decoded = json.loads(msg)
                        text = decoded.get("message", msg)
                    except Exception:
                        text = msg
                    self.message_received.emit(text)
        except Exception as e:
            self.message_received.emit(f"[!] WebSocket error: {e}")

    def stop(self):
        self._running = False
        self.quit()
