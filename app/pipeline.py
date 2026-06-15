"""
6-stage analysis pipeline (+ Stage 0 hash). Each stage appends to
result["reasons"] and may escalate result["verdict"]. Stages run in order;
once verdict reaches "malicious" the remaining stages still run (for a full
audit trail) but routing logic in main.py blocks the file regardless.

Stage 0  sha256 hash + known-bad blocklist   (always)
Stage 1  extension blocklist                 (always)
Stage 2  MIME vs declared/extension          (always)
Stage 3  entropy                             (profile)
Stage 4  isolation forest (online anomaly)   (profile)
Stage 5  clamav INSTREAM                      (profile: strict)
Stage 6  dlp sensitive-data scan             (profile: standard/strict)
"""

import io
import math
import hashlib
import logging
import zipfile
from collections import Counter
from pathlib import Path

import magic
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

from app import clamav, dlp

log = logging.getLogger(__name__)

_IF_MODEL_PATH = Path("/data/isolation_forest.joblib")
_IF_BUFFER_PATH = Path("/data/if_samples.joblib")
_if_model: IsolationForest | None = None
_if_samples: list[list[float]] = []
_if_fitted: bool = False
_if_since_fit: int = 0          # clean samples seen since last refit

# Formats whose content is *expected* to be high-entropy (already compressed or
# encrypted containers). Entropy is still recorded for these, but it is not, on
# its own, treated as a suspicious signal — otherwise every JPEG/PNG/zip/docx
# would be quarantined.
_COMPRESSED_EXTS = {
    "zip", "gz", "tgz", "bz2", "xz", "7z", "rar", "zst", "lz4",
    "jpg", "jpeg", "png", "gif", "webp", "heic",
    "mp3", "aac", "ogg", "flac", "m4a",
    "mp4", "mov", "mkv", "avi", "webm", "m4v",
    "docx", "xlsx", "pptx", "odt", "ods", "odp",
    "pdf", "epub", "apk", "jar",
}


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
    """Lazy-load model + training buffer from the persistent volume."""
    global _if_model, _if_samples, _if_fitted
    if _if_model is None:
        if _IF_MODEL_PATH.exists():
            _if_model = joblib.load(_IF_MODEL_PATH)
            _if_fitted = True
        else:
            _if_model = IsolationForest(
                contamination=contamination, random_state=42, n_estimators=100
            )
        if _IF_BUFFER_PATH.exists():
            try:
                _if_samples = joblib.load(_IF_BUFFER_PATH)
            except Exception as e:  # corrupt buffer is non-fatal
                log.warning("IF buffer load failed, starting fresh: %s", e)
                _if_samples = []
    return _if_model


def _save_if():
    if _if_model is not None:
        _IF_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(_if_model, _IF_MODEL_PATH)
        joblib.dump(_if_samples[-5000:], _IF_BUFFER_PATH)


def _load_blocklist(path: str | None) -> set[str]:
    """Load a sha256 hash blocklist (one lowercase hex digest per line, '#' comments)."""
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        log.warning("hash blocklist not found: %s", path)
        return set()
    out: set[str] = set()
    for line in p.read_text().splitlines():
        h = line.strip().lower()
        if h and not h.startswith("#"):
            out.add(h.split()[0])
    log.info("loaded %d known-bad hashes from %s", len(out), path)
    return out


# ── pipeline ──────────────────────────────────────────────────────────────────

class AnalysisResult:
    def __init__(self, filename: str, size: int):
        self.filename = filename
        self.extension = Path(filename).suffix.lower().lstrip(".")
        self.file_size = size
        self.verdict = "clean"          # clean | suspicious | malicious
        self.blocked = False
        self.reasons: list[str] = []
        self.sha256: str | None = None
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
            "sha256":         self.sha256 or "",
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
            "sha256":        self.sha256,
            "entropy":       self.entropy,
            "detected_mime": self.detected_mime,
            "if_score":      self.if_score,
            "stages_run":    self.stages_run,
        }


# Which stages each profile runs.  Stages 0/1/2 (hash + extension + MIME) always run.
# stage3=entropy  stage4=isolation_forest  stage5=clamav  stage6=dlp  stage7=archive
_PROFILE_STAGES: dict[str, set[str]] = {
    "fast":     {"stage1", "stage2"},
    "standard": {"stage1", "stage2", "stage3", "stage4", "stage6", "stage7"},
    "strict":   {"stage1", "stage2", "stage3", "stage4", "stage5", "stage6", "stage7"},
    "archive":  {"stage1", "stage2", "stage3", "stage7"},
}


class AnalysisPipeline:
    def __init__(self, config: dict):
        ml = config["ml"]
        self.entropy_threshold: float = ml["entropy_threshold"]
        self.contamination: float = ml["isolation_forest_contamination"]
        self.min_samples: int = ml["isolation_forest_min_samples"]
        self.malicious_threshold: float = ml["malicious_score_threshold"]
        # Refit the IF model once every N new clean samples instead of on every
        # upload — keeps per-request latency flat and avoids constant retraining.
        self.retrain_interval: int = int(ml.get("isolation_forest_retrain_interval", 50))

        clam = config.get("clamav", {})
        self.clamav_host: str = clam.get("host", "clamav")
        self.clamav_port: int = int(clam.get("port", 3310))
        self.clamav_timeout: int = int(clam.get("timeout", 15))

        sec = config.get("security", {})
        self.hash_blocklist: set[str] = _load_blocklist(sec.get("hash_blocklist_file"))
        # Archive (zip-bomb) guard — limits are generous enough not to trip on
        # legitimate zip/docx/xlsx, but catch the classic 1000x+ decompression bomb.
        self.archive_max_ratio: float = float(sec.get("archive_max_ratio", 150))
        self.archive_max_uncompressed_mb: int = int(sec.get("archive_max_uncompressed_mb", 2048))
        self.archive_max_entries: int = int(sec.get("archive_max_entries", 100000))

    def run(
        self,
        data: bytes,
        filename: str,
        declared_type: str | None = None,
        profile: str = "standard",
    ) -> AnalysisResult:
        result = AnalysisResult(filename, len(data))
        stages = _PROFILE_STAGES.get(profile, _PROFILE_STAGES["standard"])

        self._stage0_hash(result, data)
        self._stage1_extension(result, filename)
        self._stage2_mime(result, data, filename, declared_type)
        # Structural archive check runs before the statistical stages so a
        # detected zip-bomb can't be learned as a "clean" Isolation Forest sample.
        if "stage7" in stages:
            self._stage7_archive(result, data)
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

    # ── Stage 0: sha256 hash + known-bad blocklist ───────────────────────────
    def _stage0_hash(self, result: AnalysisResult, data: bytes):
        result.stages_run.append("hash")
        digest = hashlib.sha256(data).hexdigest()
        result.sha256 = digest
        if digest in self.hash_blocklist:
            result.flag(f"known_bad_hash: {digest[:16]}…", escalate_to="malicious")
            log.warning("stage0 blocklist HIT: %s (%s)", result.filename, digest[:16])

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
        # Compressed/encrypted container formats are *expected* to be high-entropy;
        # flagging them produces constant false positives. Record the value but
        # only treat high entropy as a signal for formats that should be low-entropy.
        if result.extension in _COMPRESSED_EXTS:
            return
        if entropy > self.entropy_threshold:
            result.flag(f"high_entropy: {entropy:.3f} > {self.entropy_threshold}")

    # ── Stage 4: Isolation Forest ─────────────────────────────────────────────
    def _stage4_isolation_forest(self, result: AnalysisResult, data: bytes, filename: str):
        result.stages_run.append("isolation_forest")
        global _if_samples, _if_model, _if_fitted, _if_since_fit

        features = _extract_features(data, filename)
        model = _load_if(self.contamination)

        # Score against the current fitted model (if any).
        if _if_fitted:
            score = float(model.score_samples(np.array([features]))[0])
            result.if_score = round(score, 4)
            if score < self.malicious_threshold:
                # Anomaly alone → suspicious. Anomaly + another signal → malicious.
                escalate = "malicious" if result.verdict != "clean" else "suspicious"
                result.flag(f"anomaly: IF_score={score:.4f}", escalate_to=escalate)

        # Train ONLY on files that look clean so far — never learn malicious/
        # suspicious samples as "normal" (prevents model poisoning).
        if result.verdict != "clean":
            return
        _if_samples.append(features)
        _if_since_fit += 1

        # Refit lazily: only after enough new clean samples accumulate, not on
        # every single upload (keeps latency flat, avoids constant retraining).
        if len(_if_samples) >= self.min_samples and (
            not _if_fitted or _if_since_fit >= self.retrain_interval
        ):
            model.fit(np.array(_if_samples[-5000:]))
            _if_fitted = True
            _if_since_fit = 0
            _save_if()
            log.info("IF refit on %d clean samples", min(len(_if_samples), 5000))

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

    # ── Stage 7: archive / zip-bomb guard ─────────────────────────────────────
    def _stage7_archive(self, result: AnalysisResult, data: bytes):
        # Only inspect real zip-family containers (zip/jar/apk/docx/xlsx/pptx).
        # Reads the central directory only — never extracts.
        if not zipfile.is_zipfile(io.BytesIO(data)):
            return
        result.stages_run.append("archive_inspect")
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()
        except Exception as e:
            log.warning("stage7 archive parse error (non-fatal): %s", e)
            return

        entries = len(infos)
        total_unc = sum(i.file_size for i in infos)
        total_comp = sum(i.compress_size for i in infos) or 1
        ratio = total_unc / total_comp

        if entries > self.archive_max_entries:
            result.flag(f"archive_bomb: {entries} entries", escalate_to="malicious")
        if total_unc > self.archive_max_uncompressed_mb * 1024 * 1024:
            result.flag(
                f"archive_bomb: uncompressed {total_unc // (1024 * 1024)}MB", escalate_to="malicious"
            )
        if ratio > self.archive_max_ratio:
            result.flag(f"archive_bomb: ratio {ratio:.0f}x", escalate_to="malicious")
        if result.verdict == "malicious":
            log.warning(
                "stage7 zip-bomb: %s entries=%d unc=%dMB ratio=%.0fx",
                result.filename, entries, total_unc // (1024 * 1024), ratio,
            )
