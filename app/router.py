import shutil
from pathlib import Path
import logging

log = logging.getLogger(__name__)


class FileRouter:
    def __init__(self, config: dict):
        self.targets: dict = config.get("targets", {})
        self.quarantine_path = Path(config["quarantine_path"])

    def allowed(self, target_name: str, filename: str) -> bool:
        target = self.targets.get(target_name)
        if not target:
            return False
        allowed_types: list[str] = target.get("allowed_types", ["*"])
        if "*" in allowed_types:
            return True
        ext = Path(filename).suffix.lower().lstrip(".")
        return ext in allowed_types

    def route(self, tmp_path: Path, filename: str, target_name: str) -> Path:
        """Move clean file to target NAS path."""
        target = self.targets.get(target_name)
        if not target:
            raise ValueError(f"Unknown target: {target_name}")
        dest_dir = Path(target["path"])
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = _unique(dest_dir / filename)
        shutil.move(str(tmp_path), dest)
        log.info("routed %s → %s", filename, dest)
        return dest

    def quarantine(self, tmp_path: Path, filename: str) -> Path:
        """Move blocked/suspicious file to quarantine. Never touches NAS paths."""
        self.quarantine_path.mkdir(parents=True, exist_ok=True)
        dest = _unique(self.quarantine_path / filename)
        shutil.move(str(tmp_path), dest)
        log.warning("quarantined %s → %s", filename, dest)
        return dest


def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    i = 1
    while True:
        candidate = path.parent / f"{stem}_{i}{suffix}"
        if not candidate.exists():
            return candidate
        i += 1
