# ------------------------------------------------------------------
#  part4_comm.py — improved ELM327 driver (drop-in)
# ------------------------------------------------------------------
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional, Tuple, List

import serial  # pyserial
from part1_core import ProtocolType


LOG = logging.getLogger("snapcore.elm327")


class ELM327Error(Exception):
    """Generic ELM327 communication error."""


class ELM327Timeout(ELM327Error):
    """Timed out waiting for a response/prompt."""


class ELM327Driver:
    """
    Minimal, robust ELM327 driver with:
      • async connect/init sequence
      • protocol selection (auto by default)
      • prompt/OK aware reads (handles '>' and 'OK')
      • line/echo sanitization, NO DATA detection
      • helper to send PIDs (e.g., '010C')

    Notes:
      - Keeps a single serial port open.
      - Runs blocking serial I/O in the default thread (pyserial is sync),
        while using small asyncio sleeps to avoid busy loops.
    """

    def __init__(
        self,
        port: str,
        baud: int = 115200,
        timeout_s: float = 2.0,
        read_prompt: bytes = b">",
    ) -> None:
        self.port = port
        self.baud = baud
        self.timeout_s = timeout_s
        self._prompt = read_prompt
        self._ser: Optional[serial.Serial] = None
        self.connected: bool = False
        self.active_protocol: Optional[ProtocolType] = None

    # ----------------------- lifecycle -----------------------

    async def connect(self, protocol: Optional[ProtocolType] = None) -> bool:
        """
        Open serial, perform a clean init:
          ATZ, ATE0, ATL0, ATS0, ATH0, ATCAF1, (optional ATSPx)
        Verifies ELM banner and leaves adapter at prompt.
        """
        self._open()
        LOG.info("Initializing ELM327 on %s @ %d", self.port, self.baud)

        # Hard reset, drain banner
        await self._command(b"ATZ", expect_ok=False, settle_s=1.0, flush_first=True)
        banner = await self._read_until_prompt()
        if b"ELM" not in banner.replace(b"\r", b""):
            LOG.warning("ELM banner not found in: %r", banner)

        # Quiet, compact, no headers (you can enable later if needed)
        await self._ok("ATE0")   # Echo off
        await self._ok("ATL0")   # Linefeeds off
        await self._ok("ATS0")   # Spaces off
        await self._ok("ATH0")   # Headers off
        await self._ok("ATCAF1") # Automatic formatting on

        # Protocol (None => auto)
        if protocol is None:
            await self._ok("ATSP0")
            self.active_protocol = None
        else:
            sp = self._protocol_to_sp(protocol)
            await self._ok(f"ATSP{sp}")
            self.active_protocol = protocol

        # Verify prompt
        await self._ensure_prompt()
        self.connected = True
        LOG.info("ELM327 ready.")
        return True

    def close(self) -> None:
        if self._ser and self._ser.is_open:
            try:
                self._ser.close()
            finally:
                self._ser = None
                self.connected = False

    # ----------------------- high level ----------------------

    async def set_protocol(self, protocol: Optional[ProtocolType]) -> None:
        """Switch protocol at runtime (None = auto)."""
        self._ensure_open()
        if protocol is None:
            await self._ok("ATSP0")
            self.active_protocol = None
        else:
            sp = self._protocol_to_sp(protocol)
            await self._ok(f"ATSP{sp}")
            self.active_protocol = protocol
        await self._ensure_prompt()

    async def query_pid(self, pid_hex: str, *, timeout: Optional[float] = None) -> bytes:
        """
        Send a hex PID like '010C' and return the raw response bytes (no CR/LF).
        Raises on 'NO DATA' or timeout.
        """
        self._ensure_open()
        if not self.connected:
            raise ELM327Error("Adapter not initialized. Call connect() first.")

        pid_hex = pid_hex.strip().replace(" ", "").upper()
        if not pid_hex or any(ch not in "0123456789ABCDEF" for ch in pid_hex):
            raise ValueError("pid_hex must be a non-empty hex string like '010C'")

        raw = await self._command(pid_hex.encode("ascii"))
        lines = self._split_lines(raw)

        # Filter ELM chatter
        data: List[bytes] = []
        for ln in lines:
            if not ln:
                continue
            if b"SEARCHING" in ln or b"BUS INIT" in ln:
                continue
            if ln == b"OK":
                continue
            if ln.startswith(b"?"):
                raise ELM327Error(f"ELM error: {ln!r}")
            if b"NO DATA" in ln:
                raise ELM327Error("NO DATA")
            if b"STOPPED" in ln:
                raise ELM327Error("STOPPED")
            data.append(ln)

        # Return last non-empty line (typical ELM behavior)
        return data[-1] if data else b""

    # ----------------------- low level -----------------------

    async def send_command(self, cmd: bytes, *, timeout: Optional[float] = None) -> bytes:
        """
        Low-level raw command (bytes, without trailing CR). Returns full raw buffer up to prompt.
        """
        return await self._command(cmd, timeout=timeout)

    # ----------------------- internals -----------------------

    def _open(self) -> None:
        if self._ser and self._ser.is_open:
            return
        try:
            self._ser = serial.Serial(
                self.port,
                self.baud,
                timeout=0,         # non-blocking reads; we handle timing
                write_timeout=2.0,
            )
            # Flush any stale data
            self._ser.reset_input_buffer()
            self._ser.reset_output_buffer()
        except Exception as e:
            raise ELM327Error(f"Failed to open {self.port}: {e}") from e

    def _ensure_open(self) -> None:
        if not self._ser or not self._ser.is_open:
            raise ELM327Error("Serial port is not open")

    async def _ok(self, at: str, *, settle_s: float = 0.02) -> None:
        buf = await self._command(at.encode("ascii"), settle_s=settle_s)
        if b"OK" not in buf:
            # some adapters omit OK but show prompt; accept if prompt seen
            if not buf.strip().endswith(self._prompt):
                raise ELM327Error(f"Expected OK for {at!r}, got {buf!r}")

    async def _command(
        self,
        cmd: bytes,
        *,
        timeout: Optional[float] = None,
        settle_s: float = 0.02,
        flush_first: bool = False,
    ) -> bytes:
        """
        Send a command (without CR), read until prompt '>' or timeout.
        Returns the entire raw buffer (including \r and prompt) for parsing.
        """
        self._ensure_open()
        ser = self._ser  # type: ignore[assignment]
        assert ser is not None

        if flush_first:
            ser.reset_input_buffer()
            ser.reset_output_buffer()

        # Write the command + CR
        try:
            ser.write(cmd + b"\r")
            ser.flush()
        except Exception as e:
            raise ELM327Error(f"Write failed for {cmd!r}: {e}") from e

        # Give the adapter a short moment to start responding
        await asyncio.sleep(settle_s)

        return await self._read_until_prompt(timeout=timeout)

    async def _read_until_prompt(self, *, timeout: Optional[float] = None) -> bytes:
        """
        Read chunks until '>' prompt is seen or the timeout elapses.
        """
        self._ensure_open()
        ser = self._ser  # type: ignore[assignment]
        assert ser is not None

        end = time.monotonic() + (timeout if timeout is not None else self.timeout_s)
        buf = bytearray()

        while time.monotonic() < end:
            try:
                chunk = ser.read(ser.in_waiting or 1)
            except Exception as e:
                raise ELM327Error(f"Read failed: {e}") from e

            if chunk:
                buf += chunk
                # ELM prompt is usually at the very end
                if self._prompt in buf:
                    break
            else:
                await asyncio.sleep(0.01)

        if self._prompt not in buf:
            # Some devices omit '>' occasionally; treat long non-empty as okay
            if not buf:
                raise ELM327Timeout(f"Timeout waiting for prompt after {self.timeout_s}s")
        return bytes(buf)

    async def _ensure_prompt(self) -> None:
        """
        If the prompt is not immediately available, send a benign command to reach it.
        """
        try:
            # Try a quick read (drain)
            raw = await self._read_until_prompt(timeout=0.2)
            if self._prompt in raw:
                return
        except ELM327Timeout:
            pass

        # Send a carriage return to nudge the adapter to print a prompt
        _ = await self._command(b"", timeout=1.0)

    # ----------------------- helpers -------------------------

    @staticmethod
    def _split_lines(raw: bytes) -> List[bytes]:
        # normalize: remove prompt, split on CR/LF, strip spaces
        raw = raw.replace(b"\r\n", b"\r").replace(b"\n", b"\r")
        raw = raw.replace(b">", b"")
        lines = [ln.strip() for ln in raw.split(b"\r")]
        # remove echoes / empties
        return [ln for ln in lines if ln]

    @staticmethod
    def _protocol_to_sp(proto: ProtocolType) -> str:
        """
        Map ProtocolType -> ATSP number (ELM327 'Set Protocol').
        Common map (per ELM docs):
          0 = Automatic
          1 = SAE J1850 PWM
          2 = SAE J1850 VPW
          3 = ISO 9141-2
          4 = ISO 14230-4 (KWP 5 baud init)
          5 = ISO 14230-4 (KWP fast init)
          6 = ISO 15765-4 CAN (11 bit, 500 kbaud)
          7 = ISO 15765-4 CAN (29 bit, 500 kbaud)
        """
        mapping = {
            ProtocolType.J1850_PWM: "1",
            ProtocolType.J1850_VPW: "2",
            ProtocolType.ISO9141: "3",
            ProtocolType.ISO14230_KWP: "5",     # prefer fast init
            ProtocolType.ISO15765_CAN_11: "6",
            ProtocolType.ISO15765_CAN_29: "7",
            # Best-effort fallbacks:
            ProtocolType.UDS: "6",     # UDS usually rides on CAN 11/29
            ProtocolType.J1939: "6",   # many ELM clones emulate via 29-bit, but 6/7 are common
        }
        try:
            return mapping[proto]
        except KeyError:
            raise ELM327Error(f"Unsupported protocol mapping for {proto!r}")
