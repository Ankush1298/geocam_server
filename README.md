# GeoCam Verification Server v0.7

This is the **browser/server side** for the GeoCam v0.7 Android APK.
It must be deployed together with the matching v0.7 APK because both use **Protocol v2**.

## What this server verifies

For every synchronized photo/video, the server independently calculates SHA-256 over the exact media bytes it receives and verifies an Ed25519 signature over:

- protocol version
- record ID
- media type
- UTC timestamp
- latitude/longitude
- accuracy
- altitude
- address
- media SHA-256

The server therefore does **not** need, and must never contain, a GeoCam private signing key.

## Files

- `app.py` — Flask verification API and browser verification page
- `storage.py` — local and remote (Postgres + bucket) storage backends
- `requirements.txt` — Python dependencies
- `Procfile` — Gunicorn/Render startup command
- `tests/test_server_protocol.py` — protocol tests

Do **not** restore the old `records.json` database. v0.7 stores records in SQLite and media files in the configured data directory.

## Render deployment (free plan)

Render's free plan has **no persistent disk**: the local filesystem is wiped on every spin-down (15 min idle) and redeploy, which deletes SQLite records and uploaded media. So the server stores data externally:

- **Records** -> Postgres (`DATABASE_URL`) - Supabase or Neon free tier
- **Media** -> S3-compatible bucket (`S3_*`) - Cloudflare R2, Supabase Storage (S3 endpoint) or Backblaze B2

```text
DATABASE_URL=postgresql://...            # use sslmode=require
S3_ENDPOINT_URL=https://<account>.r2.cloudflarestorage.com
S3_BUCKET=geocam-media
S3_ACCESS_KEY_ID=...
S3_SECRET_ACCESS_KEY=...
S3_REGION=auto
MAX_UPLOAD_MB=80
```

Open `https://YOUR-SERVER/healthz` after deploy: it must say `"storage":"remote"`. If it says `"local"`, records will still be lost on restart. If only some of the variables are set, the server refuses to start instead of silently using the disk.

Without these variables the server uses local SQLite + disk (`GEOCAM_DATA_DIR`, `GEOCAM_DB`), which is fine for local development only.

The first request after 15 idle minutes is still slow on the free plan (cold start). Data is no longer lost.

Optional device enrollment:

```text
GEOCAM_TRUSTED_PUBLIC_KEYS=<base64-public-key-1>,<base64-public-key-2>
```

If `GEOCAM_TRUSTED_PUBLIC_KEYS` is empty, the server accepts any valid Ed25519 public key. This is convenient for friend testing. For an official production trust model, populate the allow-list or implement a device enrollment/attestation service.

## Local run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python app.py
```

The server listens on port `8765` locally, or on `$PORT` when provided by the hosting platform.

## API

### `POST /sync`

Multipart form:

- `record` — JSON protocol-v2 record
- `media` — exact final JPEG/MP4 bytes whose SHA-256 is in `record.mediaSha256`

The server rejects:

- missing fields
- unsupported protocol versions
- malformed cryptographic material
- non-UTC timestamps
- invalid media hashes
- media/hash mismatches
- untrusted public keys when an allow-list is configured
- invalid Ed25519 signatures
- conflicting reuse of an existing record ID

### `GET /<record_id>`

Browser verification page. It re-hashes the stored media and re-verifies the signature before displaying **MEDIA + SIGNATURE VERIFIED**.

### `GET /<record_id>/media`

Serves the stored verified media.

## Important security rule

Never put the GeoCam device private key/seed in this server repository or in server environment variables. The server needs public keys only.

## Matching APK

Build the matching APK with:

```bash
flutter pub get
flutter analyze
flutter build apk --release --dart-define=GEOCAM_VERIFICATION_URL=https://YOUR-SERVER.example.com
```
