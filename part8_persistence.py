# ------------------------------------------------------------------
#  part8_persistence.py  –  atomic JSON save/load
# ------------------------------------------------------------------
import json, pathlib, os
from typing import Dict, Any

class VlinkPersistence:
    def __init__(self, root: pathlib.Path) -> None:
        self.root = pathlib.Path(root).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self.file = self.root / "db.json"

    def save(self, data: Dict[str, Any]) -> None:
        tmp = self.file.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.file)

    def load(self) -> Dict[str, Any]:
        if not self.file.exists():
            return {}
        with self.file.open("r", encoding="utf-8") as f:
            return json.load(f)



