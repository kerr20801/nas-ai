import logging
import os
import tempfile
from pathlib import Path

import yaml
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse

from app.analyzer import FileAnalyzer
from app.notifier import send_telegram
from app.router import FileRouter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("nas_ai")

CONFIG_PATH = os.environ.get("NAS_AI_CONFIG", "/config/config.yaml")


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


app = FastAPI(title="NAS AI", version="1.0.0")

_cfg: dict | None = None
_analyzer: FileAnalyzer | None = None
_router: FileRouter | None = None


def _get_deps():
    global _cfg, _analyzer, _router
    if _cfg is None:
        _cfg = load_config()
        _analyzer = FileAnalyzer(_cfg)
        _router = FileRouter(_cfg)
    return _cfg, _analyzer, _router


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/upload")
async def upload(
    file: UploadFile = File(...),
    target: str = Query(..., description="Target name defined in config.yaml"),
    declared_type: str | None = Query(None, description="MIME type from client"),
):
    cfg, analyzer, router = _get_deps()

    max_bytes = cfg["server"].get("max_file_mb", 500) * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(413, f"File exceeds {cfg['server']['max_file_mb']} MB limit")

    filename = Path(file.filename or "upload").name  # strip path traversal

    if not router.allowed(target, filename):
        raise HTTPException(
            415,
            f"File type not allowed for target '{target}'",
        )

    result = analyzer.analyse(data, filename, declared_type)
    verdict = result["verdict"]

    # Write to temp file so router can move it atomically
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)

    try:
        dest = router.route(tmp_path, filename, target, verdict)
    except Exception as e:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(500, str(e)) from e

    result["dest"] = str(dest)

    # Telegram notification
    tg = cfg.get("telegram", {})
    notify_on: list[str] = tg.get("notify_on", [])
    if verdict in notify_on and tg.get("bot_token") and "YOUR_BOT_TOKEN" not in tg["bot_token"]:
        send_telegram(tg["bot_token"], tg["chat_id"], result, target)

    log.info(
        "upload: file=%s target=%s verdict=%s entropy=%.3f",
        filename, target, verdict, result["entropy"],
    )

    status_code = 200 if verdict == "clean" else 202
    return JSONResponse(status_code=status_code, content={
        "verdict": verdict,
        "filename": filename,
        "target": target,
        "dest": result["dest"],
        "entropy": result["entropy"],
        "detected_mime": result["detected_mime"],
        "if_score": result["if_score"],
        "reasons": result["reasons"],
    })
