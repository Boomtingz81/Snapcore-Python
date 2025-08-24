# ------------------------------------------------------------------
#  part8_persistence.py — atomic JSON save/load (+ backups)
# ------------------------------------------------------------------
from __future__ import annotations
import json, os, pathlib, time
from typing import Dict, Any, Optional

class VlinkPersistence:
    """
    Tiny atomic JSON store.
    - Atomic writes via temp file + os.replace
    - Optional rolling backups: file.json.bak1 .. bakN
    - Graceful load on empty/malformed JSON
    """

    def __init__(
        self,
        root: pathlib.Path | str,
        filename: str = "db.json",
        *,
        keep_backups: int = 2,        # how many .bak files to keep
        schema_version: int = 1       # bump if structure changes
    ) -> None:
        self.root = pathlib.Path(root).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self.file = self.root / filename
        self.keep_backups = max(0, int(keep_backups))
        self.schema_version = int(schema_version)

    # ----------------------- public API -----------------------

    def save(self, data: Dict[str, Any], *, pretty: bool = True) -> None:
        """
        Atomically write JSON to disk.
        - pretty=True adds indent and stable keys for diffs
        """
        payload = {
            "_schema": self.schema_version,
            "_saved_at": int(time.time()),
            "data": data,
        }
        tmp = self.file.with_suffix(self.file.suffix + ".tmp")

        # Serialize first so we fail before touching disk state
        text = json.dumps(payload, indent=2 if pretty else None, sort_keys=pretty)

        with tmp.open("w", encoding="utf-8") as f:
            f.write(text)

        # rotate backups before replacing
        self._rotate_backups()

        # Atomic swap
        os.replace(tmp, self.file)

    def load(self) -> Dict[str, Any]:
        """
        Load JSON. If file is missing/empty/malformed, returns {}.
        """
        if not self.file.exists():
            return {}
        try:
            with self.file.open("r", encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError, ValueError):
            # Try latest backup if present
            backup = self._latest_backup()
            if backup:
                try:
                    with backup.open("r", encoding="utf-8") as f:
                        raw = json.load(f)
                except Exception:
                    return {}
            else:
                return {}

        if isinstance(raw, dict) and "data" in raw:
            return raw.get("data", {}) or {}
        # Backward-compat: old flat format
        return raw if isinstance(raw, dict) else {}

    def load_or_init(self, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Load, or initialize with default (persisted immediately)."""
        obj = self.load()
        if obj:
            return obj
        obj = default or {}
        self.save(obj)
        return obj

    def backup_now(self) -> Optional[pathlib.Path]:
        """Create an immediate backup copy of the current file."""
        if not self.file.exists():
            return None
        dst = self._backup_path(1)  # will be shifted by rotate anyway
        self._rotate_backups()
        try:
            # simple copy to bak1
            contents = self.file.read_bytes()
            dst.write_bytes(contents)
            return dst
        finally:
            self._prune_excess_backups()

    def restore_backup(self, index: int = 1) -> bool:
        """
        Replace current file with backup N (1 = most recent).
        Returns True if restored.
        """
        bak = self._backup_path(index)
        if not bak.exists():
            return False
        tmp = self.file.with_suffix(self.file.suffix + ".restore.tmp")
        tmp.write_bytes(bak.read_bytes())
        os.replace(tmp, self.file)
        return True

    # ---------------------- internals ------------------------

    def _backup_path(self, index: int) -> pathlib.Path:
        return self.file.with_name(self.file.name + f".bak{index}")

    def _latest_backup(self) -> Optional[pathlib.Path]:
        for i in range(1, self.keep_backups + 1):
            p = self._backup_path(i)
            if p.exists():
                return p
        return None

    def _rotate_backups(self) -> None:
        if self.keep_backups <= 0:
            return
        # Shift bakN → bakN+1 (prune tail), then new file will become bak1
        for i in range(self.keep_backups, 0, -1):
            src = self._backup_path(i)
            dst = self._backup_path(i + 1)
            if dst.exists():
                try:
                    dst.unlink()
                except OSError:
                    pass
            if src.exists():
                try:
                    os.replace(src, dst)
                except OSError:
                    pass
        # Move current file → bak1 (if it exists)
        if self.file.exists():
            try:
                os.replace(self.file, self._backup_path(1))
            except OSError:
                pass
        self._prune_excess_backups()

    def _prune_excess_backups(self) -> None:
        # remove any bak > keep_backups
        i = self.keep_backups + 1
        while True:
            p = self._backup_path(i)
            if not p.exists():
                break
            try:
                p.unlink()
            except OSError:
                pass
            i += 1
