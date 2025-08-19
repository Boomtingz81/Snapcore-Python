# ------------------------------------------------------------------
#  part4_comm.py  –  improved ELM327 driver (drop-in)
# ------------------------------------------------------------------
import asyncio, serial, logging
from part1_core import ProtocolType

class ELM327Driver:
    def __init__(self, port: str, baud: int = 115200) -> None:
        self.ser = serial.Serial(port, baud, timeout=1)
        self.connected = False

    async def connect(self) -> bool:
        """ATZ → ATE0 → ATL0 → ATSP0 → ready."""
        self.ser.write(b"ATZ\r")
        await asyncio.sleep(1)
        if b"ELM" not in self.ser.read_all():
            return False

        for cmd in (b"ATE0", b"ATL0", b"ATSP0"):
            self.ser.write(cmd + b"\r")
            await asyncio.sleep(0.1)
            self.ser.read_all()  # discard echo
        self.connected = True
        return True

    async def send_command(self, cmd: bytes, *, timeout: float = 1.0) -> bytes:
        if not self.connected:
            raise ConnectionError("Not connected")
        self.ser.write(cmd + b"\r")
        self.ser.flush()
        await asyncio.sleep(timeout)
        raw = self.ser.read_all()
        lines = [ln.strip() for ln in raw.split(b"\r") if ln.strip()]
        # last non-empty line is the response
        return lines[-1] if lines else b""


