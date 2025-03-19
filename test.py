import asyncio
import websockets
import json

async def send_test_message():
    async with websockets.connect("ws://localhost:8765") as websocket:
        await websocket.send(json.dumps({"message": "✅ WebSocket Test Message from Client"}))

asyncio.run(send_test_message())
