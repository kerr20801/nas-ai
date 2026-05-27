import math
import os
import tempfile
from collections import Counter
from pathlib import Path

import magic
from sklearn.ensemble import IsolationForest
import numpy as np
import joblib

_if_model: IsolationForest | None = None
_if_samples: list[list[float]] = []
_IF_MODEL_PATH = Path("/data/isolation_forest.joblib")


def _load_or_init_model(contamination: float) -> IsolationForest:
    global _if_model
    if _if_model is None:
        if _IF_MODEL_PATH.exists():
            _if_model = joblib.load(_IF_MODEL_PATH)
        else:
            _if_model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100,
            )
    return _if_model


def _save_model():
    if _if_model is not None:
        _IF_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(_if_model, _IF_MODEL_PATH)


def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def extract_features(data: bytes, filename: str) -> list[float]:
    size = len(data)
    entropy = calc_entropy(data)
    ext = Path(filename).suffix.lower().lstrip(".")

    # byte-level stats
    counts = Counter(data)
    null_ratio = counts.get(0, 0) / max(size, 1)
    printable = sum(1 for b in data if 32 <= b < 127)
    printable_ratio = printable / max(size, 1)

    # PE header heuristic (MZ magic)
    is_pe = 1.0 if data[:2] == b"MZ" else 0.0
    is_elf = 1.0 if data[:4] == b"\x7fELF" else 0.0
    is_script = 1.0 if ext in {"sh", "ps1", "bat", "cmd", "vbs", "js"} else 0.0
    is_archive = 1.0 if ext in {"zip", "tar", "gz", "7z", "rar", "bz2"} else 0.0

    return [
        math.log1p(size),
        entropy,
        null_ratio,
        printable_ratio,
        is_pe,
        is_elf,
        is_script,
        is_archive,
    ]


class FileAnalyzer:
    def __init__(self, config: dict):
        self.entropy_threshold: float = config["ml"]["entropy_threshold"]
        self.contamination: float = config["ml"]["isolation_forest_contamination"]
        self.min_samples: int = config["ml"]["isolation_forest_min_samples"]
        self.malicious_threshold: float = config["ml"]["malicious_score_threshold"]
        _load_or_init_model(self.contamination)

    def analyse(self, data: bytes, filename: str, declared_type: str | None = None) -> dict:
        result = {
            "filename": filename,
            "size": len(data),
            "verdict": "clean",
            "reasons": [],
            "entropy": 0.0,
            "detected_mime": None,
            "if_score": None,
        }

        # MIME detection
        detected_mime = magic.from_buffer(data, mime=True)
        result["detected_mime"] = detected_mime

        if declared_type and declared_type != "application/octet-stream":
            declared_norm = declared_type.split(";")[0].strip().lower()
            if detected_mime != declared_norm:
                result["reasons"].append(
                    f"mime_mismatch: declared={declared_norm} detected={detected_mime}"
                )

        # Entropy
        entropy = calc_entropy(data)
        result["entropy"] = round(entropy, 4)
        if entropy > self.entropy_threshold:
            result["reasons"].append(f"high_entropy: {entropy:.3f} > {self.entropy_threshold}")

        # Isolation Forest
        features = extract_features(data, filename)
        global _if_samples, _if_model
        _if_samples.append(features)

        if len(_if_samples) >= self.min_samples:
            X = np.array(_if_samples[-5000:])  # rolling window
            _if_model.fit(X)
            _save_model()

            score = float(_if_model.score_samples(np.array([features]))[0])
            result["if_score"] = round(score, 4)
            if score < self.malicious_threshold:
                result["reasons"].append(f"anomaly: IF score={score:.4f}")

        # Final verdict
        reason_types = {r.split(":")[0] for r in result["reasons"]}
        if "anomaly" in reason_types and (
            "high_entropy" in reason_types or "mime_mismatch" in reason_types
        ):
            result["verdict"] = "malicious"
        elif result["reasons"]:
            result["verdict"] = "suspicious"

        return result
