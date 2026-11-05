# NAS AI — System Status

> Last updated: 2026-06-15
> Phases 1–3 + hardening complete · verified 23 unit + 7 Docker e2e
> Deploy: Docker Compose (FastAPI :8900 + ClamAV sidecar)

NAS-agnostic by design — targets route to any path (local dir or NAS mount), so the whole system runs and is testable without physical NAS hardware. Point `config.yaml` targets at a NAS mount when one is available; no code change needed.

---

## Architecture

```
Any device upload
    ↓
HAProxy (routing + rate limit)
    ↓
NAS AI Service (FastAPI :8900) — profile-driven pipeline
    ↓ clean only        ↓ suspicious / malicious
Route to NAS target   Quarantine (never reaches NAS) + TG alert
    │
    └─ every analysis → Logstash HTTP → Elasticsearch nas-ai-events-*
```

**Core principle:** analysis is centralised, storage is distributed. Only `clean` files reach the NAS; anything suspicious or malicious is quarantined.

---

## Pipeline (8 stages; 0/1/2 always run)

| # | Stage | Profiles | Verdict on hit |
|---|-------|----------|----------------|
| 0 | SHA256 + known-bad hash blocklist | all | malicious |
| 1 | Extension blocklist (21 exec/script types) | all | malicious |
| 2 | MIME detection (libmagic) + ext/declared cross-check | all | malicious / suspicious |
| 3 | Entropy (skips compressed/encrypted container formats) | standard, strict, archive | suspicious |
| 4 | Isolation Forest (clean-only online training, lazy refit) | standard, strict | suspicious / malicious |
| 5 | ClamAV INSTREAM | strict | malicious |
| 6 | DLP (credentials + Taiwan PII) | standard, strict | suspicious |
| 7 | Archive / zip-bomb guard (runs before stats stages) | standard, strict, archive | malicious |

**Profiles:** `fast` = 0,1,2 · `standard` = +3,4,6,7 · `strict` = +5 · `archive` = 0,1,2,3,7

### Verdicts & HTTP

| Status | Verdict | Routing |
|--------|---------|---------|
| 200 | clean | → NAS target |
| 202 | suspicious | → quarantine |
| 400 | malicious / high-confidence suspicious | → quarantine (blocked) |
| 413 | — | file over `max_file_mb` |
| 415 | — | type not in target `allowed_types` (pre-pipeline) |

---

## Security

- **API key** — optional `X-API-Key` on `/upload`, enforced when `security.api_key` is set (else 401).
- **Hash blocklist** (Stage 0) — `security.hash_blocklist_file`, one sha256 per line; instant reject, cheaper than ClamAV. sha256 recorded on every event for dedup/correlation.
- **Zip-bomb guard** (Stage 7) — ratio / total-uncompressed / entry-count caps; reads the zip central directory only, never extracts.
- **Anti-poisoning** — Isolation Forest trains only on files that pass clean; flagged files are never learned as "normal".
- **Routing invariant** — only `clean` files are written to a NAS target; a DLP-flagged secret (suspicious) is quarantined, not routed.

---

## ELK / observability

When `logstash.url` is set, every analysis is sent fire-and-forget to a Logstash HTTP input → Elasticsearch `nas-ai-events-*`. ES index template is `dynamic: strict` and maps every emitted field including `sha256` (keyword) and `dlp_findings` (object). Logstash configs + templates live in `logstash/`. TG alerts fire independently for verdicts in `telegram.notify_on`.

Join key across indices: `source_ip` (ip) + `nas_user` (keyword).

---

## Verification

| Layer | Coverage | Result |
|-------|----------|--------|
| Unit (standalone harness, no NAS/Docker/ClamAV) | entropy fix, hash blocklist, IF anti-poison + lazy refit, DLP regex, zip-bomb | 23 / 23 ✅ |
| Docker e2e (real container + real ClamAV) | auth 401, clean→NAS, blocked ext, EICAR virus, DLP→quarantine, blocklist, 415 | 7 / 7 ✅ |

---

## Deployment

```bash
cp config.example.yaml config.yaml          # set targets, quarantine, telegram, security
cp hash_blocklist.example.txt hash_blocklist.txt   # optional Stage 0 list
docker compose up -d --build
curl http://localhost:8900/health
```

**Build note:** on hosts where BuildKit's build sandbox can't reach apt mirrors (while the host can), use the legacy builder: `DOCKER_BUILDKIT=0 docker compose build && docker compose up -d --no-build`. See CLAUDE.md Gotchas.

Run with `--workers 1` (IF model state is per-process) until model state is moved to a shared store.

---

## Change log

| Date | Change |
|------|--------|
| 2026-06-15 | **Hardening**: Stage 0 hash blocklist · Stage 7 zip-bomb guard · API key auth · entropy false-positive fix (compressed formats) · poison-resistant IF (clean-only, lazy refit, persisted buffer) · tighter DLP password matcher · routing fix (suspicious files no longer reach NAS) · ES template maps sha256 + dlp_findings |
| Phase 3 | DLP sensitive-data detection (credentials + Taiwan PII) |
| Phase 2 | ClamAV sidecar + profile-driven pipeline |
| Phase 1 | FastAPI + MIME + entropy + Isolation Forest + Telegram + routing |
