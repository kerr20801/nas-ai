# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the service

```bash
# Build and start (first run pulls ClamAV image + ~300 MB definitions)
docker compose up -d --build

# Health check
curl http://localhost:8900/health

# Test upload — clean file to standard profile target
curl -X POST "http://localhost:8900/upload?target=home&nas_user=alice" \
  -F "file=@/path/to/file.pdf"

# Test ClamAV detection (strict profile) — EICAR test string
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
curl -X POST "http://localhost:8900/upload?target=company&nas_user=alice" \
  -F "file=@/tmp/eicar.txt"
# Expected: verdict=malicious, blocked=true, clamav_verdict="virus:Eicar-Test-Signature"

# Logs
docker logs -f nas-ai
docker logs -f nas-ai-clamav
```

## Architecture

**Request flow:** `POST /upload` → `router.allowed()` (415 if type denied) → `pipeline.run()` (profile-driven stages) → `router.route/quarantine()` → `es_sender.send_event()` (fire-and-forget) → `notifier.send_telegram()` (if configured)

### `app/pipeline.py` — core analysis

`AnalysisPipeline.run(data, filename, declared_type, profile)` selects stages via `_PROFILE_STAGES`:

| Profile | Stages run |
|---------|-----------|
| `fast` | 1 + 2 |
| `standard` | 1 + 2 + 3 + 4 |
| `strict` | 1 + 2 + 3 + 4 + **5** |
| `archive` | 1 + 2 + 3 |

1. **Stage 1 – Extension blocklist**: instant `malicious` for exe/dll/bat/ps1/vbs/js etc.
2. **Stage 2 – MIME check**: `python-magic` detects actual type; flags mismatch vs declared type or extension
3. **Stage 3 – Entropy**: Shannon entropy > threshold → `suspicious`
4. **Stage 4 – Isolation Forest**: 8-feature vector (size, entropy, null\_ratio, printable\_ratio, PE/ELF/script/archive flags); model trains online and persists to `/data/isolation_forest.joblib`
5. **Stage 5 – ClamAV** (strict only): INSTREAM TCP scan via `app/clamav.py`; virus hit → `malicious`; clamd unavailable → non-fatal warning, upload proceeds

Blocking rule:
- `malicious` → always blocked (HTTP 400)
- `suspicious` with both `high_entropy` AND `mime_mismatch` → also blocked (HTTP 400)
- `suspicious` with single signal → quarantine only (HTTP 202)

`AnalysisResult.to_es_event()` produces the exact ES schema payload (includes `clamav_verdict`). `to_dict()` is the legacy format for the TG notifier.

### `app/clamav.py` — ClamAV INSTREAM scanner

`scan(data, host, port, timeout)` — streams bytes to `clamd` over TCP.
Returns: `"clean"` | `"virus:<name>"` | `"error:<reason>"`. Never raises.

### `app/main.py` — FastAPI endpoint

`/upload` takes `file`, `target` (required), `declared_type` (optional MIME claim), `nas_user` (defaults to `"anonymous"`). Source IP from `Request.client.host`.

`_get_deps()` lazy-initialises config, pipeline, and router once per worker process on first request — not at import time.

### `app/router.py` — file routing

`FileRouter.allowed(target, filename)` runs **before** the pipeline — a type rejection returns HTTP 415, not a pipeline verdict. `allowed_types: ["*"]` accepts everything.

`FileRouter.route()` moves clean files to `targets[name].path`; `quarantine()` moves blocked/suspicious files to `quarantine_path`. Both use `shutil.move` (works with local dirs or NAS mount points). `_unique()` appends `_1`, `_2` … on filename collision.

### `app/notifier.py` — Telegram alert

`send_telegram()` reads `result.to_dict()` (legacy format, not `to_es_event()`). Sends HTML-formatted message via `curl -4`. Only fires when `verdict in notify_on` and `bot_token` is set and not the placeholder string.

### `app/es_sender.py` — Logstash event

`send_event(url, payload)` — `subprocess.run` curl with 3s timeout. Never raises. If `logstash.url` is missing from config, ES logging is silently skipped.

## Config

`config.yaml` (gitignored) is mounted at `/config/config.yaml` inside the container. Copy from `config.example.yaml`. Key sections:

- `targets[name].profile` — controls which pipeline stages run (`fast`/`standard`/`strict`/`archive`)
- `targets[name].allowed_types` — extension whitelist; `["*"]` accepts all
- `logstash.url` — HTTP endpoint for Logstash `nas-ai-events` pipeline (omit to disable ES logging)
- `clamav.host` / `clamav.port` — clamd TCP address (default: `clamav:3310`, the Docker service name)
- `ml.isolation_forest_min_samples` — IF doesn't score until this many files seen (default 30)

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
