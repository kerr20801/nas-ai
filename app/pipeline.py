"""
4-stage analysis pipeline. Each stage appends to result["reasons"] and may
escalate result["verdict"]. Stages run in order; if verdict reaches
"malicious" after any stage, remaining stages still run (for full audit
trail) but routing logic in main.py will block the file regardless.
"""

import math
import logging
from collections import Counter
from pathlib import Path

import magic
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

from app import clamav, dlp

log = logging.getLogger(__name__)

_IF_MODEL_PATH = Path("/data/isolation_forest.joblib")
_if_model: IsolationForest | None = None
_if_samples: list[list[float]] = []


# ── helpers ──────────────────────────────────────────────────────────────────

def _calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _extract_features(data: bytes, filename: str) -> list[float]:
    size = len(data)
    entropy = _calc_entropy(data)
    ext = Path(filename).suffix.lower().lstrip(".")
    counts = Counter(data)
    null_ratio = counts.get(0, 0) / max(size, 1)
    printable_ratio = sum(1 for b in data if 32 <= b < 127) / max(size, 1)
    return [
        math.log1p(size),
        entropy,
        null_ratio,
        printable_ratio,
        1.0 if data[:2] == b"MZ" else 0.0,              # PE
        1.0 if data[:4] == b"\x7fELF" else 0.0,          # ELF
        1.0 if ext in {"sh", "ps1", "bat", "cmd", "vbs", "js"} else 0.0,
        1.0 if ext in {"zip", "tar", "gz", "7z", "rar", "bz2"} else 0.0,
    ]


def _load_if(contamination: float) -> IsolationForest:
    global _if_model
    if _if_model is None:
        if _IF_MODEL_PATH.exists():
            _if_model = joblib.load(_IF_MODEL_PATH)
        else:
            _if_model = IsolationForest(
                contamination=contamination, random_state=42, n_estimators=100
            )
    return _if_model


def _save_if():
    if _if_model is not None:
        _IF_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(_if_model, _IF_MODEL_PATH)


# ── pipeline ──────────────────────────────────────────────────────────────────

class AnalysisResult:
    def __init__(self, filename: str, size: int):
        self.filename = filename
        self.extension = Path(filename).suffix.lower().lstrip(".")
        self.file_size = size
        self.verdict = "clean"          # clean | suspicious | malicious
        self.blocked = False
        self.reasons: list[str] = []
        self.entropy: float = 0.0
        self.detected_mime: str | None = None
        self.declared_mime: str | None = None
        self.mime_match: bool = True
        self.if_score: float | None = None
        self.clamav_verdict: str | None = None
        self.dlp_findings: list[dict] = []
        self.stages_run: list[str] = []

    def flag(self, reason: str, escalate_to: str = "suspicious"):
        self.reasons.append(reason)
        if escalate_to == "malicious" or (
            escalate_to == "suspicious" and self.verdict == "clean"
        ):
            self.verdict = escalate_to

    def to_es_event(self, source_ip: str, nas_user: str, target: str, profile: str = "standard") -> dict:
        """Build the exact payload expected by the nas-ai-events ES schema."""
        return {
            "source_ip":      source_ip,
            "nas_user":       nas_user.lower(),
            "target":         target,
            "profile":        profile,
            "filename":       self.filename,
            "extension":      self.extension,
            "file_size":      self.file_size,
            "detected_mime":  self.detected_mime or "",
            "declared_mime":  self.declared_mime or "",
            "mime_match":     self.mime_match,
            "entropy":        round(self.entropy, 4),
            "verdict":        self.verdict,
            "blocked":        self.blocked,
            "clamav_verdict": self.clamav_verdict or "",
            "dlp_findings":   self.dlp_findings,
            "reasons":        self.reasons,
            "stages_run":     self.stages_run,
        }

    def to_dict(self) -> dict:
        """Legacy dict for Telegram notifier."""
        return {
            "filename":      self.filename,
            "size":          self.file_size,
            "verdict":       self.verdict,
            "blocked":       self.blocked,
            "reasons":       self.reasons,
            "entropy":       self.entropy,
            "detected_mime": self.detected_mime,
            "if_score":      self.if_score,
            "stages_run":    self.stages_run,
        }


# Which stages each profile runs.  All profiles always run stages 1 & 2 (extension + MIME).
# stage3=entropy  stage4=isolation_forest  stage5=clamav
_PROFILE_STAGES: dict[str, set[str]] = {
    "fast":     {"stage1", "stage2"},
    "standard": {"stage1", "stage2", "stage3", "stage4", "stage6"},
    "strict":   {"stage1", "stage2", "stage3", "stage4", "stage5", "stage6"},
    "archive":  {"stage1", "stage2", "stage3"},
}


class AnalysisPipeline:
    def __init__(self, config: dict):
        ml = config["ml"]
        self.entropy_threshold: float = ml["entropy_threshold"]
        self.contamination: float = ml["isolation_forest_contamination"]
        self.min_samples: int = ml["isolation_forest_min_samples"]
        self.malicious_threshold: float = ml["malicious_score_threshold"]

        clam = config.get("clamav", {})
        self.clamav_host: str = clam.get("host", "clamav")
        self.clamav_port: int = int(clam.get("port", 3310))
        self.clamav_timeout: int = int(clam.get("timeout", 15))

    def run(
        self,
        data: bytes,
        filename: str,
        declared_type: str | None = None,
        profile: str = "standard",
    ) -> AnalysisResult:
        result = AnalysisResult(filename, len(data))
        stages = _PROFILE_STAGES.get(profile, _PROFILE_STAGES["standard"])

        self._stage1_extension(result, filename)
        self._stage2_mime(result, data, filename, declared_type)

        if "stage3" in stages:
            self._stage3_entropy(result, data)
        if "stage4" in stages:
            self._stage4_isolation_forest(result, data, filename)
        if "stage5" in stages:
            self._stage5_clamav(result, data)
        if "stage6" in stages:
            self._stage6_dlp(result, data, filename)

        # Blocking rule: malicious verdict always blocks.
        # suspicious verdict blocks only when entropy AND mime_mismatch both fired
        # (two independent signals — stronger confidence).
        reason_types = {r.split(":")[0] for r in result.reasons}
        if result.verdict == "malicious":
            result.blocked = True
        elif result.verdict == "suspicious" and reason_types >= {"high_entropy", "mime_mismatch"}:
            result.blocked = True

        return result

    # ── Stage 1: extension blocklist (fast, no I/O) ──────────────────────────
    def _stage1_extension(self, result: AnalysisResult, filename: str):
        result.stages_run.append("extension_check")
        ext = Path(filename).suffix.lower().lstrip(".")
        BLOCKED_EXTS = {
            "exe", "dll", "bat", "cmd", "com", "scr", "pif",
            "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "ps2",
            "msi", "msp", "msc", "reg", "hta",
        }
        if ext in BLOCKED_EXTS:
            result.flag(f"blocked_extension: .{ext}", escalate_to="malicious")
            log.warning("stage1 blocked: %s (.%s)", filename, ext)

    # ── Stage 2: MIME vs declared type ───────────────────────────────────────
    def _stage2_mime(
        self,
        result: AnalysisResult,
        data: bytes,
        filename: str,
        declared_type: str | None,
    ):
        result.stages_run.append("mime_check")
        detected = magic.from_buffer(data, mime=True)
        result.detected_mime = detected

        ext = Path(filename).suffix.lower().lstrip(".")
        DANGEROUS_MIMES = {
            "application/x-dosexec",
            "application/x-executable",
            "application/x-sharedlib",
            "application/x-msdownload",
        }
        if detected in DANGEROUS_MIMES:
            result.flag(f"dangerous_mime: {detected}", escalate_to="malicious")
            return

        # Extension ↔ detected MIME cross-check
        EXT_MIME_MAP = {
            "pdf": "application/pdf",
            "jpg": "image/jpeg", "jpeg": "image/jpeg",
            "png": "image/png",
            "gif": "image/gif",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "zip": "application/zip",
            "txt": "text/plain",
        }
        expected = EXT_MIME_MAP.get(ext)
        if expected and detected != expected:
            result.mime_match = False
            result.flag(f"mime_mismatch: ext=.{ext} expected={expected} detected={detected}")

        # Declared type vs actual
        if declared_type and declared_type != "application/octet-stream":
            declared_norm = declared_type.split(";")[0].strip().lower()
            result.declared_mime = declared_norm
            if detected != declared_norm and "mime_mismatch" not in " ".join(result.reasons):
                result.mime_match = False
                result.flag(f"mime_mismatch: declared={declared_norm} detected={detected}")

    # ── Stage 3: entropy ─────────────────────────────────────────────────────
    def _stage3_entropy(self, result: AnalysisResult, data: bytes):
        result.stages_run.append("entropy")
        entropy = _calc_entropy(data)
        result.entropy = round(entropy, 4)
        if entropy > self.entropy_threshold:
            result.flag(f"high_entropy: {entropy:.3f} > {self.entropy_threshold}")

    # ── Stage 4: Isolation Forest ─────────────────────────────────────────────
    def _stage4_isolation_forest(self, result: AnalysisResult, data: bytes, filename: str):
        result.stages_run.append("isolation_forest")
        global _if_samples, _if_model

        features = _extract_features(data, filename)
        _if_samples.append(features)

        model = _load_if(self.contamination)

        if len(_if_samples) < self.min_samples:
            log.debug("IF: not enough samples (%d/%d)", len(_if_samples), self.min_samples)
            return

        X = np.array(_if_samples[-5000:])
        model.fit(X)
        _save_if()

        score = float(model.score_samples(np.array([features]))[0])
        result.if_score = round(score, 4)

        if score < self.malicious_threshold:
            # Anomaly alone → suspicious. Anomaly + another signal → malicious.
            escalate = "malicious" if result.verdict != "clean" else "suspicious"
            result.flag(f"anomaly: IF_score={score:.4f}", escalate_to=escalate)

    # ── Stage 5: ClamAV INSTREAM ──────────────────────────────────────────────
    def _stage5_clamav(self, result: AnalysisResult, data: bytes):
        result.stages_run.append("clamav")
        verdict = clamav.scan(
            data,
            host=self.clamav_host,
            port=self.clamav_port,
            timeout=self.clamav_timeout,
        )
        result.clamav_verdict = verdict

        if verdict.startswith("virus:"):
            virus_name = verdict[6:]
            result.flag(f"clamav: {virus_name}", escalate_to="malicious")
            log.warning("stage5 ClamAV HIT: %s — %s", result.filename, virus_name)
        elif verdict.startswith("error:"):
            # ClamAV unavailable or scan error — log but don't block
            log.warning("stage5 ClamAV error (non-fatal): %s", verdict)
        else:
            log.debug("stage5 ClamAV clean: %s", result.filename)

    # ── Stage 6: DLP ──────────────────────────────────────────────────────────
    def _stage6_dlp(self, result: AnalysisResult, data: bytes, filename: str):
        result.stages_run.append("dlp")
        findings = dlp.scan(data, filename)
        if not findings:
            return

        result.dlp_findings = findings
        types = [f["type"] for f in findings]
        result.flag(f"dlp: {', '.join(types)}", escalate_to="suspicious")
        log.warning("stage6 DLP hit: %s — %s", filename, types)
