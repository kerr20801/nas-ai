# NAS AI

ML-powered file upload security gateway. Sits in front of your NAS and blocks malicious files before they land on storage.

**Core principle: analysis is centralised, storage is distributed. Bad files never reach the NAS.**

Every upload runs through a profile-driven pipeline (extension → MIME → entropy → anomaly ML → virus scan → DLP). Clean files are routed to the target NAS; suspicious files are quarantined; malicious files are rejected with an HTTP 4xx — the NAS never sees them.

---

## How it works

```
Any device uploads
    ↓
HAProxy VM (routing + rate limit)
    ↓
NAS AI Service (Docker) — profile-driven pipeline
  │
  ├─ Stage 0: SHA256 hash + known-bad blocklist (instant reject)
  ├─ Stage 1: Extension blocklist (exe/dll/ps1/bat/vbs … instant reject)
  ├─ Stage 2: MIME detection (libmagic — catches renamed executables)
  ├─ Stage 3: Entropy analysis (>7.2 → packed/encrypted = suspicious)
  ├─ Stage 4: Isolation Forest (anomaly scoring, online learning)
  ├─ Stage 5: ClamAV virus scan  ← strict profile only
  └─ Stage 6: DLP sensitive data ← standard + strict profiles
  │
  ↓ clean              ↓ suspicious          ↓ blocked (malicious)
Route to NAS        Quarantine            HTTP 400 — rejected
                    HTTP 202              Never touches NAS
                    TG alert              TG alert
                                          (event → Logstash/ES either way)

NAS-A / NAS-B / NAS-C (firewall allows writes from this service only)
```

---

## Profiles

A target's `profile` decides which stages run, trading thoroughness for latency. Set per target in `config.yaml`.

| Profile | Stages run | Use for |
|---------|-----------|---------|
| `fast` | 1 + 2 | Trusted internal sources, high volume |
| `standard` | 1 + 2 + 3 + 4 + 6 | Default — full analysis minus virus scan |
| `strict` | 1 + 2 + 3 + 4 + 5 + 6 | Untrusted uploads — adds ClamAV |
| `archive` | 1 + 2 + 3 | Bulk binary archival — skips ML/DLP |

Stages 0, 1 & 2 (hash + extension + MIME) always run regardless of profile — they are near-free and catch the highest-confidence threats.

---

## Pipeline stages

| # | Stage | Verdict on hit | Detail |
|---|-------|----------------|--------|
| 0 | **Hash blocklist** | malicious | SHA256 computed for every file; match against known-bad list → instant reject |
| 1 | **Extension blocklist** | malicious | 21 executable/script extensions — instant reject, no I/O |
| 2 | **MIME detection** | malicious / suspicious | libmagic detects real type; dangerous MIME → malicious, type mismatch → suspicious |
| 3 | **Entropy** | suspicious | Shannon entropy > threshold (packed/encrypted content) |
| 4 | **Isolation Forest** | suspicious / malicious | 8-feature anomaly score; anomaly alone → suspicious, anomaly + another signal → malicious |
| 5 | **ClamAV** | malicious | INSTREAM TCP scan; clamd unavailable is non-fatal (upload proceeds) |
| 6 | **DLP** | suspicious | Sensitive data in text files; never blocks on its own |

**Blocked extensions (Stage 1):** `exe dll bat cmd com scr pif vbs vbe js jse wsf wsh ps1 ps2 msi msp msc reg hta`

**Dangerous MIME types (Stage 2):** `application/x-dosexec`, `application/x-executable`, `application/x-sharedlib`, `application/x-msdownload` — flagged regardless of file extension, so a renamed `evil.exe → photo.jpg` is still caught.

**Stage 2 also cross-checks** the detected MIME against both the file extension (`pdf`, `jpg`, `png`, `docx`, `xlsx`, `pptx`, `zip`, `txt`…) and the client-declared `declared_type`. Either mismatch sets `mime_match: false` and flags `mime_mismatch`.

**Hash blocklist (Stage 0):** every file's SHA256 is computed up front and matched against `security.hash_blocklist_file` (one hex digest per line). A hit is rejected instantly — cheaper than ClamAV and effective against known samples. The digest is also recorded on every event for dedup / cross-event correlation in ES.

**Entropy & compressed formats (Stage 3):** the entropy value is always recorded, but for formats that are *expected* to be high-entropy (zip/gz/7z, jpg/png/mp4, docx/xlsx/pptx, pdf…) it is **not** treated as a suspicious signal — otherwise every legitimate image or Office document would be quarantined. Entropy only flags formats that should be low-entropy (txt, csv, log, source…).

**Isolation Forest features (Stage 4):** `log1p(size)`, Shannon entropy, null-byte ratio, printable-byte ratio, PE flag (`MZ` magic), ELF flag (`\x7fELF`), script-extension flag, archive-extension flag. The model **trains only on files that pass clean** — flagged files are never learned as "normal", which prevents an attacker from poisoning the baseline by uploading many similar malicious files. It refits lazily (every `isolation_forest_retrain_interval` new clean samples, default 50) rather than on every request, and the model + training buffer persist to a Docker volume (`/data/`). Cold start: the first `isolation_forest_min_samples` (default 30) files bypass scoring while the model gathers a baseline.

---

## Verdicts & HTTP responses

| Status | Verdict | Blocked | Meaning |
|--------|---------|---------|---------|
| `200` | clean | No | Routed to target NAS path |
| `202` | suspicious | No* | Quarantined + TG alert (ops review) |
| `400` | malicious | **Yes** | Quarantined + TG alert — upload rejected |
| `413` | — | — | File exceeds `max_file_mb` limit |
| `415` | — | — | File type not in target's `allowed_types` (rejected before pipeline) |

\* `suspicious` is **also** blocked (400) when `high_entropy` AND `mime_mismatch` fire simultaneously — two independent signals = high confidence.

**Blocking** means the file never reaches NAS storage. Blocked files are still copied to `quarantine_path` so the ops team can review them; the client gets an explicit HTTP 4xx so the uploader knows the transfer was rejected.

---

## Quick start

```bash
cp config.example.yaml config.yaml
# edit config.yaml — set targets, quarantine_path, telegram

docker compose up -d --build
# first run pulls the ClamAV image + ~300 MB of virus definitions

curl http://localhost:8900/health      # {"status":"ok"}
```

---

## API

### `GET /health`

Liveness probe. Returns `{"status": "ok"}`.

### `POST /upload`

| Param | In | Required | Default | Description |
|-------|-----|----------|---------|-------------|
| `file` | multipart | ✅ | — | The file to upload |
| `target` | query | ✅ | — | Target name defined in `config.yaml` |
| `declared_type` | query | | — | MIME type the client claims (cross-checked in Stage 2) |
| `nas_user` | query | | `anonymous` | Username for audit trail / ES join key |

```bash
# Route to "home" target
curl -X POST "http://localhost:8900/upload?target=home&nas_user=alice" \
  -F "file=@/path/to/document.pdf"

# Route to "company" with a declared MIME claim
curl -X POST "http://localhost:8900/upload?target=company&declared_type=application/pdf&nas_user=alice" \
  -F "file=@/path/to/report.pdf"
```

#### Response

```json
{
  "verdict": "clean",
  "blocked": false,
  "filename": "report.pdf",
  "target": "company",
  "dest": "/mnt/nas-company/uploads/report.pdf",
  "file_size": 84213,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
  "entropy": 5.231,
  "detected_mime": "application/pdf",
  "declared_mime": "application/pdf",
  "mime_match": true,
  "if_score": 0.12,
  "clamav_verdict": "clean",
  "dlp_findings": [],
  "reasons": [],
  "stages_run": ["extension_check", "mime_check", "entropy", "isolation_forest", "clamav", "dlp"]
}
```

`if_score` is `null` until the IF cold-start threshold is reached; `clamav_verdict` is `null` unless the target uses the `strict` profile. The uploaded filename is reduced to its basename (`Path(...).name`) to strip path-traversal attempts.

---

## Testing

```bash
# Clean file → 200, verdict=clean
curl -X POST "http://localhost:8900/upload?target=home&nas_user=alice" \
  -F "file=@/path/to/file.pdf"

# ClamAV detection (strict profile) — EICAR test string → 400, verdict=malicious
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
curl -X POST "http://localhost:8900/upload?target=company&nas_user=alice" \
  -F "file=@/tmp/eicar.txt"
# → clamav_verdict="virus:Eicar-Test-Signature"

# DLP detection (standard/strict) — private key → 202, verdict=suspicious
printf -- '-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n-----END RSA PRIVATE KEY-----\n' > /tmp/test_key.txt
curl -X POST "http://localhost:8900/upload?target=home&nas_user=alice" \
  -F "file=@/tmp/test_key.txt"
# → dlp_findings=[{"type":"private_key","count":1}]

# Logs
docker logs -f nas-ai
docker logs -f nas-ai-clamav
```

---

## Configuration

```yaml
server:
  host: "0.0.0.0"
  port: 8900
  max_file_mb: 500

targets:
  home:
    path: "/mnt/nas-home/incoming"
    profile: "standard"
    allowed_types: ["*"]          # * = accept all passing files
  company:
    path: "/mnt/nas-company/uploads"
    profile: "strict"
    allowed_types: ["pdf", "docx", "xlsx", "pptx", "txt", "csv", "jpg", "png"]

quarantine_path: "/mnt/quarantine"

# Stage 0 — known-bad SHA256 blocklist (one hex digest per line). Omit to disable.
security:
  hash_blocklist_file: "/config/hash_blocklist.txt"

clamav:
  host: "clamav"      # Docker service name; use IP if running externally
  port: 3310
  timeout: 15

ml:
  entropy_threshold: 7.2                  # > this = suspicious (encrypted/packed)
  isolation_forest_contamination: 0.05    # expected anomaly ratio
  isolation_forest_min_samples: 30        # start scoring after N files seen
  isolation_forest_retrain_interval: 50   # refit once every N new clean samples
  malicious_score_threshold: -0.1         # IF score below this = anomaly

# Optional — sends analysis events to a Logstash HTTP input. Omit to disable.
logstash:
  url: "http://logstash-host:10544"

telegram:
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"
  notify_on: ["suspicious", "malicious", "mime_mismatch"]   # add "clean" to log everything
```

**Adding a new NAS:** add an entry under `targets`, map its mount point, pick a profile. No code changes needed — `path` can be a local directory or a NAS mount, the router treats them identically.

---

## Detection signals

| Signal | Stage | Verdict | How |
|--------|-------|---------|-----|
| **Known-bad hash** | 0 | malicious | SHA256 matches the configured blocklist |
| **Blocked extension** | 1 | malicious | exe/dll/bat/ps1/vbs/js etc. — instant reject |
| **Dangerous MIME** | 2 | malicious | libmagic detects PE/ELF regardless of extension |
| **MIME mismatch** | 2 | suspicious | declared or extension type ≠ detected type |
| **High entropy** | 3 | suspicious | Shannon entropy > 7.2 (packed/encrypted content) |
| **Isolation Forest** | 4 | suspicious/malicious | anomaly on 8-feature vector; anomaly + another signal → malicious |
| **Virus signature** | 5 | malicious | ClamAV INSTREAM scan (strict profile only) |
| **Sensitive data** | 6 | suspicious | credentials / PII in text files (standard + strict) |

### DLP patterns (Stage 6)

Scans only text-extractable formats (`txt csv json yaml toml ini env py js sh sql pem crt key …`); binary files are skipped entirely. Reads at most the first 512 KB (large text files are truncated, not skipped).

| Type | Method |
|------|--------|
| `private_key` | PEM header regex (RSA/EC/DSA/OPENSSH/PGP) |
| `aws_key` | `AKIA…` prefix |
| `github_token` | `ghp_` / `github_pat_` prefix |
| `api_credential` | `api_key` / `secret_key` / `access_token` / `bearer` assignment |
| `plaintext_password` | `password=` / `passwd=` / `pwd=` assignment |
| `jwt` | three-segment base64url pattern |
| `credit_card` | digit run + **Luhn checksum** (cuts false positives) |
| `taiwan_id` | letter+digit format + **national-ID checksum** |

DLP findings raise `suspicious` but never block on their own — they surface secrets/PII without disrupting legitimate transfers.

---

## Observability (optional)

When `logstash.url` is set, every analysis (clean or not) is sent fire-and-forget to a Logstash HTTP input → Elasticsearch `nas-ai-events-*`. The event carries `source_ip`, `nas_user`, `target`, `profile`, verdict, all detection fields, and `stages_run`. Logstash configs and ES index templates live in `logstash/`. If Logstash is down the upload is unaffected — sending never blocks or raises.

Telegram alerts fire independently for any verdict listed in `telegram.notify_on`.

---

## Project structure

```
app/
  main.py        FastAPI app — /upload, /health, routing & response codes
  pipeline.py    6-stage analysis pipeline + AnalysisResult
  clamav.py      ClamAV INSTREAM TCP scanner
  dlp.py         DLP regex + checksum scanner
  router.py      target routing / quarantine / type allow-list
  notifier.py    Telegram HTML alerts (curl -4)
  es_sender.py   fire-and-forget Logstash event sender
logstash/        pipeline configs + ES index templates
config.example.yaml
docker-compose.yml   nas-ai + clamav sidecar
Dockerfile
```

**Tech stack:** Python 3.12 · FastAPI + uvicorn · python-magic (libmagic) · scikit-learn (Isolation Forest) · ClamAV · Docker Compose.

---

## Notes & limitations

- **Single worker per model.** The Isolation Forest trains in-process and persists to the `nas-ai-data` volume. Under multi-worker uvicorn each worker keeps its own model state — keep `--workers 1` or move the model to a shared store before scaling.
- **ClamAV first start** downloads ~300 MB of definitions; `depends_on: service_healthy` + a 120 s healthcheck `start_period` makes nas-ai wait. ClamAV unavailability is non-fatal by design (so a clamd restart/update can't take uploads down).
- **DLP is text-only.** Encrypted archives and binary office formats are not parsed for sensitive content.

---

## Roadmap

- **Phase 1** ✅: FastAPI + MIME + Entropy + Isolation Forest + Telegram + file routing
- **Phase 2** ✅: ClamAV sidecar (Stage 5) + profile-driven pipeline (`fast`/`standard`/`strict`/`archive`)
- **Phase 3** ✅: DLP sensitive data detection — credentials (private key/AWS/GitHub/JWT) + Taiwan PII (ID checksum + credit card Luhn)
- **Hardening** ✅: Stage 0 SHA256 hash blocklist · entropy false-positive fix for compressed formats · poison-resistant Isolation Forest (clean-only online training, lazy refit, persisted buffer) · tighter DLP password matcher

---

## License

MIT
