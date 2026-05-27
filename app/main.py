import logging
import os
import tempfile
from pathlib import Path

import yaml
from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse

from app.pipeline import AnalysisPipeline
from app.notifier import send_telegram
from app.router import FileRouter
from app.es_sender import send_event

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("nas_ai")

CONFIG_PATH = os.environ.get("NAS_AI_CONFIG", "/config/config.yaml")


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


app = FastAPI(title="NAS AI", version="1.1.0")

_cfg: dict | None = None
_pipeline: AnalysisPipeline | None = None
_router: FileRouter | None = None


def _get_deps():
    global _cfg, _pipeline, _router
    if _cfg is None:
        _cfg = load_config()
        _pipeline = AnalysisPipeline(_cfg)
        _router = FileRouter(_cfg)
    return _cfg, _pipeline, _router


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),
    target: str = Query(..., description="Target name defined in config.yaml"),
    declared_type: str | None = Query(None, description="MIME type claimed by client"),
    nas_user: str = Query("anonymous", description="Username reported by the client"),
):
    cfg, pipeline, router = _get_deps()
    source_ip = request.client.host if request.client else "unknown"

    max_bytes = cfg["server"].get("max_file_mb", 500) * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(413, f"File exceeds {cfg['server']['max_file_mb']} MB limit")

    filename = Path(file.filename or "upload").name  # strip path traversal

    if not router.allowed(target, filename):
        raise HTTPException(415, f"File type not allowed for target '{target}'")

    # ── Run the pipeline (profile-driven stage selection) ────────────────────
    profile = cfg["targets"].get(target, {}).get("profile", "standard")
    result = pipeline.run(data, filename, declared_type, profile=profile)
    verdict = result.verdict
    blocked = result.blocked

    log.info(
        "upload: file=%s target=%s verdict=%s blocked=%s entropy=%.3f stages=%s",
        filename, target, verdict, blocked, result.entropy, result.stages_run,
    )

    # ── Routing ───────────────────────────────────────────────────────────────
    dest: str | None = None

    if blocked:
        # File never reaches NAS — quarantine if suspicious-but-blocked,
        # or just discard buffer if malicious (no disk trace on NAS).
        # We still quarantine so ops team can review.
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        try:
            dest = str(router.quarantine(tmp_path, filename))
        except Exception as e:
            tmp_path.unlink(missing_ok=True)
            log.error("quarantine failed: %s", e)
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        try:
            dest = str(router.route(tmp_path, filename, target))
        except Exception as e:
            tmp_path.unlink(missing_ok=True)
            raise HTTPException(500, str(e)) from e

    # ── Send event to Logstash → ES ───────────────────────────────────────────
    ls_url = cfg.get("logstash", {}).get("url")
    if ls_url:
        send_event(ls_url, result.to_es_event(source_ip, nas_user, target, profile))

    # ── Telegram notification ─────────────────────────────────────────────────
    tg = cfg.get("telegram", {})
    notify_on: list[str] = tg.get("notify_on", [])
    if verdict in notify_on and tg.get("bot_token") and "YOUR_BOT_TOKEN" not in tg["bot_token"]:
        send_telegram(tg["bot_token"], tg["chat_id"], result.to_dict(), target)

    # ── HTTP response ─────────────────────────────────────────────────────────
    # 400 = blocked (malicious or high-confidence suspicious) — upload rejected
    # 202 = quarantined (suspicious, under review) — accepted but isolated
    # 200 = clean — routed to NAS
    if blocked:
        status_code = 400
    elif verdict == "suspicious":
        status_code = 202
    else:
        status_code = 200

    return JSONResponse(
        status_code=status_code,
        content={
            "verdict": verdict,
            "blocked": blocked,
            "filename": filename,
            "target": target,
            "dest": dest,
            "file_size": result.file_size,
            "entropy": result.entropy,
            "detected_mime": result.detected_mime,
            "declared_mime": result.declared_mime,
            "mime_match": result.mime_match,
            "if_score": result.if_score,
            "clamav_verdict": result.clamav_verdict,
            "reasons": result.reasons,
            "stages_run": result.stages_run,
        },
    )
