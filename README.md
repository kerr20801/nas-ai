# NAS AI

ML-powered file upload security gateway. Sits in front of your NAS and blocks malicious files before they land on storage.

**Core principle: analysis is centralised, storage is distributed. Bad files never reach the NAS.**

---

## How it works

```
Any device uploads
    ↓
HAProxy VM (routing + rate limit)
    ↓
NAS AI Service (Docker) — 4-stage pipeline
  │
  ├─ Stage 1: Extension blocklist (exe/dll/ps1/bat/vbs … instant reject)
  ├─ Stage 2: MIME detection (libmagic — catches renamed executables)
  ├─ Stage 3: Entropy analysis (>7.2 → packed/encrypted = suspicious)
  └─ Stage 4: Isolation Forest (anomaly scoring, online learning)
  │
  ↓ clean              ↓ suspicious          ↓ blocked (malicious)
Route to NAS        Quarantine            HTTP 400 — rejected
                    HTTP 202              Never touches NAS
                    TG alert              TG alert

NAS-A / NAS-B / NAS-C (firewall allows writes from this service only)
```

---

## Verdicts & HTTP responses

| Verdict | HTTP | Blocked | Action |
|---------|------|---------|--------|
| `clean` | 200 | No | Routed to target NAS path |
| `suspicious` | 202 | No* | Quarantined + TG alert (ops review) |
| `malicious` | 400 | **Yes** | Quarantined + TG alert — upload rejected |

\* `suspicious` is also blocked (400) when entropy AND mime_mismatch both fire simultaneously — two independent signals = high confidence.

**Blocking** means the file never reaches NAS storage. The client gets an explicit HTTP 4xx so the uploader knows the transfer was rejected.

---

## Quick start

```bash
cp config.example.yaml config.yaml
# edit config.yaml — set targets, quarantine_path, telegram

docker compose up -d
```

### Upload a file

```bash
# Route to "home" target
curl -X POST "http://localhost:8900/upload?target=home" \
  -F "file=@/path/to/document.pdf"

# Route to "company" target with declared MIME
curl -X POST "http://localhost:8900/upload?target=company&declared_type=application/pdf" \
  -F "file=@/path/to/report.pdf"
```

### Response

```json
{
  "verdict": "clean",
  "filename": "report.pdf",
  "target": "company",
  "dest": "/mnt/nas-company/uploads/report.pdf",
  "entropy": 5.231,
  "detected_mime": "application/pdf",
  "if_score": 0.12,
  "reasons": []
}
```

HTTP 200 = clean, HTTP 202 = suspicious/malicious (file quarantined).

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
    allowed_types: ["*"]
  company:
    path: "/mnt/nas-company/uploads"
    allowed_types: ["pdf", "docx", "xlsx", "pptx", "txt", "csv", "jpg", "png"]

quarantine_path: "/mnt/quarantine"

ml:
  entropy_threshold: 7.2
  isolation_forest_contamination: 0.05
  isolation_forest_min_samples: 30    # start scoring after N files seen
  malicious_score_threshold: -0.1

telegram:
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"
  notify_on: ["suspicious", "malicious", "mime_mismatch"]
```

Adding a new NAS: add a new entry under `targets` and map its mount point. No code changes needed.

---

## Detection signals

| Signal | How | Threshold |
|--------|-----|-----------|
| **High entropy** | Shannon entropy on raw bytes | > 7.2 (packed/encrypted) |
| **MIME mismatch** | libmagic detection vs declared type | any mismatch |
| **Isolation Forest** | Anomaly score on 8 features (size, entropy, null ratio, printable ratio, PE/ELF/script/archive flags) | score < -0.1 |

Verdict escalation: anomaly + (entropy OR mime) → `malicious`. Any single signal → `suspicious`.

The Isolation Forest model is trained online — it learns from every file it sees and saves the model to a Docker volume. Cold-start: first 30 files are scored but not by IF (uses entropy + MIME only).

---

## Roadmap

- **Phase 1** ✅: FastAPI + MIME + Entropy + Isolation Forest + Telegram + file routing
- **Phase 2** ✅: ClamAV sidecar (Stage 5) + profile-driven pipeline (`fast`/`standard`/`strict`/`archive`)
- **Phase 3**: Sensitive data detection (PII/credentials) + duplicate detection (SHA-256 dedup)

---

## License

MIT
