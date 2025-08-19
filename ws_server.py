# ws_server.py

import json

import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from fastapi.middleware.cors import CORSMiddleware

# Optional: import your diagnostic controller if needed

# from vlink_suite.part9_controller import VLinkController

app = FastAPI()

# Enable CORS so frontend can connect

app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)

# Store connected clients

clients = set()

@app.websocket("/ws/obd")

async def obd_socket(websocket: WebSocket):

    await websocket.accept()

    clients.add(websocket)

    print("🚗 Client connected.")

    try:

        while True:

            data = await websocket.receive_text()

            print("⬅️ Received:", data)

            # For now: echo it back with dummy reply

            await websocket.send_text(f"🔧 Received: {data}")

            # Later we'll decode real commands here

    except WebSocketDisconnect:

        print("❌ Client disconnected.")

        clients.remove(websocket)






