"""
AnarkisHunter — utils_resume.py
=================================
Resume interrupted scans dari checkpoint file di logs/.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from config.settings import LOGS_DIR


class ScanCheckpoint:
    """Save/load scan progress untuk --resume."""

    def __init__(self, target: str, checkpoint_dir: Optional[Path] = None):
        self.target = target
        self.dir = checkpoint_dir or LOGS_DIR
        self.dir.mkdir(exist_ok=True)
        safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")[:80]
        self.file = self.dir / f"checkpoint_{safe_target}.json"
        self.data: Dict = {
            "target": target,
            "started": datetime.now().isoformat(),
            "completed_modules": [],
            "findings_count": 0,
            "phase": "",
        }

    def load(self) -> bool:
        """Load checkpoint jika ada. Returns True jika checkpoint ditemukan."""
        if not self.file.exists():
            return False
        try:
            self.data = json.loads(self.file.read_text(encoding="utf-8"))
            return True
        except (json.JSONDecodeError, OSError):
            return False

    def save(self):
        self.data["updated"] = datetime.now().isoformat()
        self.file.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def mark_completed(self, module_name: str):
        if module_name not in self.data["completed_modules"]:
            self.data["completed_modules"].append(module_name)
        self.save()

    def is_completed(self, module_name: str) -> bool:
        return module_name in self.data.get("completed_modules", [])

    def get_remaining(self, all_modules: List[str]) -> List[str]:
        done: Set[str] = set(self.data.get("completed_modules", []))
        return [m for m in all_modules if m not in done]

    def set_phase(self, phase: str):
        self.data["phase"] = phase
        self.save()

    def clear(self):
        if self.file.exists():
            self.file.unlink()

    @property
    def completed_count(self) -> int:
        return len(self.data.get("completed_modules", []))
