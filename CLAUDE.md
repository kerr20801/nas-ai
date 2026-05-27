# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the service

```bash
# Build and start
docker compose up -d --build

# Health check
curl http://localhost:8900/health

# Test upload
curl -X POST "http://localhost:8900/upload?target=home&nas_user=alice" \
  -F "file=@/path/to/file.pdf"

# Logs
docker logs -f nas-ai
```

## Architecture

**Request flow:** `POST /upload` → `pipeline.py` (4 stages) → `router.py` (move file) → `es_sender.py` (async event) + `notifier.py` (TG)

### `app/pipeline.py` — core analysis

`AnalysisPipeline.run(data, filename, declared_type, profile)` selects stages via `_PROFILE_STAGES`:

| Profile | Stages |
|---------|--------|
| `fast` | 1 + 2 |
| `standard` | 1 + 2 + 3 + 4 |
| `strict` | 1 + 2 + 3 + 4 + **5** |
| `archive` | 1 + 2 + 3 |

1. **Stage 1 – Extension blocklist**: instant `malicious` for exe/dll/bat/ps1/vbs/js etc.
2. **Stage 2 – MIME check**: `python-magic` detects actual type; flags mismatch vs declared type or extension
3. **Stage 3 – Entropy**: Shannon entropy > threshold → `suspicious`
4. **Stage 4 – Isolation Forest**: 8-feature vector (size, entropy, null\_ratio, printable\_ratio, PE/ELF/script/archive flags); model trains online and persists to `/data/isolation_forest.joblib`
5. **Stage 5 – ClamAV** (strict only): INSTREAM TCP scan via `app/clamav.py`; virus hit → `malicious`; clamd unavailable → non-fatal warning, upload proceeds

Blocking rule in `run()`:
- `malicious` verdict → always blocked (HTTP 400)
- `suspicious` with both `high_entropy` AND `mime_mismatch` reasons → also blocked (HTTP 400)
- `suspicious` with single signal → quarantine only (HTTP 202)

`AnalysisResult.to_es_event()` produces the exact payload for the ES schema (includes `clamav_verdict`). `to_dict()` is the legacy format for the TG notifier.

### `app/clamav.py` — ClamAV INSTREAM scanner

`scan(data, host, port, timeout)` — sends bytes to `clamd` via INSTREAM protocol over TCP.
Returns: `"clean"` | `"virus:<name>"` | `"error:<reason>"`. Never raises.

### `app/main.py` — FastAPI endpoint

`/upload` takes `file`, `target` (required), `declared_type` (optional MIME claim), `nas_user` (defaults to `"anonymous"`). Source IP comes from `Request.client.host`.

After pipeline: calls `send_event()` (fire-and-forget, never blocks upload), then `send_telegram()` if verdict matches `notify_on`.

### `app/router.py` — file routing

`FileRouter.route()` moves clean files to `targets[name].path`; `FileRouter.quarantine()` moves blocked/suspicious files to `quarantine_path`. Both use `shutil.move` so paths can be local dirs or NAS mount points interchangeably.

### `app/es_sender.py` — Logstash event

`send_event(url, payload)` — `subprocess.run` curl with 3s timeout. Never raises. URL configured via `config.yaml logstash.url`. If omitted, ES logging is silently skipped.

## Config

`config.yaml` (gitignored) is mounted at `/config/config.yaml` inside the container. Copy from `config.example.yaml`. Key sections:

- `logstash.url` — HTTP endpoint for Logstash `nas-ai-events` pipeline (default: `http://172.16.32.35:10544`)
- `targets[name].profile` — controls which pipeline stages run (`fast`/`standard`/`strict`/`archive`)
- `ml.isolation_forest_min_samples` — IF doesn't score until this many files seen (default 30)
- `clamav.host` / `clamav.port` — clamd TCP address (default: `clamav:3310`, the Docker service name)

## ELK stack (Logstash on 172.16.32.35)

Two pipelines deployed at `/etc/logstash/conf.d/`:

| File | Input | ES index |
|---|---|---|
| `nas-syslog.conf` | UDP/TCP **5514** | `nas-syslog-YYYY.MM.dd` |
| `nas-ai-events.conf` | HTTP **10544** | `nas-ai-events-YYYY.MM.dd` |

Both use `manage_template => false` — ES index templates were manually installed by the `elastic` superuser (the `syslog` Logstash user lacks `manage_index_templates`). Templates are in `logstash/templates/`.

**Join key across indices:** `source_ip` (ES `ip` type) + `nas_user` (keyword).

Logstash source files in `logstash/` are the canonical reference; deployed configs have `${ES_PASSWORD}` substituted with the hardcoded syslog user password.

## Gotchas

- Port **514** is privileged — non-root Logstash cannot bind it. Use **5514** for syslog input.
- Port **5044** is reserved for Beats (Filebeat/Auditbeat). Use **10544** for the HTTP input.
- Logstash ECS mode injects `@version`, `host`, `event`, `url`, `user_agent`, `http` fields. These must be stripped in the filter `remove_field` step or ES strict mapping rejects the document.
- `if [type]` conditions in the Logstash output block fail silently when `type` is removed in the filter cleanup step — use unconditional output blocks in single-pipeline configs.
- The IF model trains in-process. In multi-worker uvicorn (`--workers N`), each worker has its own model state. Keep `--workers 1` or move model state to a shared store before scaling.
- ClamAV first-start downloads ~300 MB of virus definitions. `depends_on: service_healthy` ensures nas-ai waits. `start_period: 120s` in the healthcheck gives it time.
- ClamAV unavailability is non-fatal by design — `error:unavailable` is logged but does not block the upload. This prevents clamd restart/update from taking the upload service down.
