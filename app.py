import base64
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Flask, abort, jsonify, render_template_string, request, send_file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "80")) * 1024 * 1024

DATA_DIR = Path(os.environ.get("GEOCAM_DATA_DIR", "./data"))
MEDIA_DIR = DATA_DIR / "media"
DB_PATH = Path(os.environ.get("GEOCAM_DB", str(DATA_DIR / "records.sqlite3")))
MEDIA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TRUSTED_PUBLIC_KEYS = {x.strip() for x in os.environ.get("GEOCAM_TRUSTED_PUBLIC_KEYS", "").split(",") if x.strip()}

HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GeoCam Verification</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;background:#f0f2f5;padding:20px;max-width:720px;margin:auto;color:#111}
.card{background:#fff;padding:24px;border-radius:16px;box-shadow:0 4px 16px rgba(0,0,0,.06)}
h2{margin:0 0 6px}.muted{color:#666;font-size:13px}.valid{background:#e8f5e9;border-left:5px solid #16843b;padding:16px;margin-top:20px;border-radius:8px}.invalid{background:#ffebee;border-left:5px solid #c62828;padding:16px;margin-top:20px;border-radius:8px}.field{margin:10px 0;word-break:break-word}.field span{font-weight:700;display:inline-block;min-width:120px}.hash{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;background:#f7f7f7;padding:10px;border-radius:8px;word-break:break-all}.media{max-width:100%;border-radius:12px;margin-top:16px}.btn{display:inline-block;padding:10px 14px;border-radius:9px;background:#111;color:#fff;text-decoration:none;margin-top:10px}
</style></head><body><div class="card">
<h2>GeoCam Verifier</h2><div class="muted">Record ID: <strong>{{ record_id }}</strong></div>
{% if error %}<div class="invalid"><h3>❌ VERIFICATION FAILED</h3><p>{{ error }}</p></div>
{% elif result %}
<div class="valid"><h3>✅ MEDIA + SIGNATURE VERIFIED</h3><p>The server's stored media bytes match the SHA-256 digest covered by the Ed25519 signature.</p></div>
{% if result.mediaType == 'photo' %}<img class="media" src="/{{ result.id }}/media" alt="GeoCam verified media">{% endif %}
<div class="field"><span>GPS:</span>{{ '%.6f'|format(result.latitude) if result.latitude is not none else 'Unavailable' }}, {{ '%.6f'|format(result.longitude) if result.longitude is not none else 'Unavailable' }}</div>
<div class="field"><span>Accuracy:</span>{{ ('±%.1f m'|format(result.accuracy)) if result.accuracy is not none else 'Unavailable' }}</div>
<div class="field"><span>Altitude:</span>{{ ('%.1f m'|format(result.altitude)) if result.altitude is not none else 'Unavailable' }}</div>
<div class="field"><span>Captured:</span>{{ result.timestamp }}</div>
<div class="field"><span>Address:</span>{{ result.address or 'None' }}</div>
<div class="field"><span>Media:</span>{{ result.mediaType }}</div>
<div class="field"><span>Device key:</span>{{ result.keyFingerprint }}</div>
<div class="field"><span>Media SHA-256:</span><div class="hash">{{ result.mediaSha256 }}</div></div>
<div class="field"><span>Signature:</span><div class="hash">{{ result.signature }}</div></div>
<a class="btn" href="/{{ result.id }}/media">Open original verified media</a>
{% endif %}</div></body></html>
"""


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS records (
            id TEXT PRIMARY KEY,
            protocol_version INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            accuracy REAL,
            altitude REAL,
            address TEXT NOT NULL,
            media_type TEXT NOT NULL,
            signature TEXT NOT NULL,
            media_sha256 TEXT NOT NULL,
            public_key TEXT NOT NULL,
            media_path TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_records_public_key ON records(public_key)")


def rv(record, camel, snake=None):
    try:
        return record[camel]
    except (KeyError, IndexError):
        return record[snake] if snake else None


def canonical(record):
    # Must match HashService._canonical in the Flutter app exactly.
    address_b64 = base64.b64encode(record["address"].encode("utf-8")).decode("ascii")
    return "|".join([
        "v=2",
        f"id={record['id']}",
        f"type={rv(record, 'mediaType', 'media_type')}",
        f"ts={record['timestamp']}",
        f"lat={fmt(record['latitude'], 6)}",
        f"lng={fmt(record['longitude'], 6)}",
        f"acc={fmt(record['accuracy'], 1)}",
        f"alt={fmt(record['altitude'], 1)}",
        f"addr64={address_b64}",
        f"media_sha256={rv(record, 'mediaSha256', 'media_sha256')}",
    ]).encode("utf-8")


def fmt(value, places):
    if value is None:
        return "null"
    return f"{float(value):.{places}f}"


def validate_record(r):
    required = ["id", "timestamp", "mediaType", "signature", "mediaSha256", "publicKey"]
    missing = [k for k in required if k not in r]
    if missing:
        raise ValueError("Missing fields: " + ", ".join(missing))
    if r.get("protocolVersion") != 2:
        raise ValueError("Unsupported protocol version")
    if not isinstance(r["id"], str) or not (3 <= len(r["id"]) <= 120):
        raise ValueError("Invalid record id")
    if r["mediaType"] not in ("photo", "video"):
        raise ValueError("Invalid media type")
    if not SHA256_RE.fullmatch(r["mediaSha256"]):
        raise ValueError("Invalid media SHA-256")
    try:
        sig = base64.b64decode(r["signature"], validate=True)
        pub = base64.b64decode(r["publicKey"], validate=True)
        if len(sig) != 64 or len(pub) != 32:
            raise ValueError("Invalid Ed25519 key/signature length")
    except Exception as e:
        raise ValueError("Invalid base64 cryptographic material") from e
    dt = datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
    if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(dt):
        raise ValueError("Timestamp must be UTC ISO-8601")
    return r["timestamp"]


def verify_signature(r):
    try:
        pub_raw = rv(r, "publicKey", "public_key")
        sig_raw = rv(r, "signature", "signature")
        if not pub_raw or not sig_raw:
            return False
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_raw, validate=True))
        sig = base64.b64decode(sig_raw, validate=True)
        pub.verify(sig, canonical(r))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError, IndexError):
        return False


def key_fingerprint(public_key):
    return hashlib.sha256(base64.b64decode(public_key)).hexdigest()[:16]


def row_to_result(row):
    result = dict(row)
    result["keyFingerprint"] = key_fingerprint(result["public_key"])
    result["mediaType"] = result.pop("media_type")
    result["mediaSha256"] = result.pop("media_sha256")
    result["publicKey"] = result.pop("public_key")
    result["mediaPath"] = result.pop("media_path")
    return result


init_db()


@app.get("/")
def index():
    return "<h2>GeoCam Verification Server is running</h2><p>Scan a GeoCam QR code to verify a record.</p>"


@app.post("/sync")
def sync_record():
    if "media" not in request.files or "record" not in request.form:
        return jsonify(error="Multipart fields 'record' and 'media' are required"), 400
    try:
        record = json.loads(request.form["record"])
        timestamp = validate_record(record)
        record["timestamp"] = timestamp
        media = request.files["media"]
        if not media.filename:
            raise ValueError("Empty media file")
        raw = media.read()
        if not raw:
            raise ValueError("Empty media file")
        if len(raw) > app.config["MAX_CONTENT_LENGTH"]:
            raise ValueError("Media too large")
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != record["mediaSha256"]:
            raise ValueError("Media SHA-256 does not match signed record")
        if TRUSTED_PUBLIC_KEYS and record["publicKey"] not in TRUSTED_PUBLIC_KEYS:
            raise ValueError("This device public key is not enrolled on the verification server")
        if not verify_signature(record):
            return jsonify(error="Ed25519 signature is invalid"), 400

        extension = "mp4" if record["mediaType"] == "video" else "jpg"
        media_path = MEDIA_DIR / f"{record['id']}.{extension}"
        with db() as conn:
            existing = conn.execute("SELECT * FROM records WHERE id=?", (record["id"],)).fetchone()
            if existing:
                if existing["signature"] != record["signature"] or existing["media_sha256"] != record["mediaSha256"]:
                    return jsonify(error="Record ID already exists with different cryptographic content"), 409
                return jsonify(success=True, id=record["id"], alreadyExists=True)
            tmp = media_path.with_suffix(media_path.suffix + ".tmp")
            tmp.write_bytes(raw)
            tmp.replace(media_path)
            conn.execute("""INSERT INTO records
                (id, protocol_version, timestamp, latitude, longitude, accuracy, altitude, address,
                 media_type, signature, media_sha256, public_key, media_path, created_at)
                VALUES (?,2,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (record["id"], record["timestamp"], record.get("latitude"), record.get("longitude"),
                 record.get("accuracy"), record.get("altitude"), record.get("address", ""),
                 record["mediaType"], record["signature"], record["mediaSha256"], record["publicKey"],
                 str(media_path), datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")))
        return jsonify(success=True, id=record["id"], verified=True)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:
        app.logger.exception("sync failure")
        return jsonify(error="Server error while storing record"), 500


@app.get("/<record_id>")
def verify_record(record_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
    if not row:
        return render_template_string(HTML, record_id=record_id, error="Record not found. The phone may not have synchronized it yet.")
    if not Path(row["media_path"]).exists():
        return render_template_string(HTML, record_id=record_id, error="The verified record exists, but its media file is unavailable on the server.")
    raw = Path(row["media_path"]).read_bytes()
    media_ok = hashlib.sha256(raw).hexdigest() == row["media_sha256"]
    sig_ok = verify_signature(row)
    if not (media_ok and sig_ok):
        return render_template_string(HTML, record_id=record_id, error="The stored media or signed metadata failed cryptographic verification.")
    return render_template_string(HTML, record_id=record_id, result=row_to_result(row))


@app.get("/<record_id>/media")
def media(record_id):
    with db() as conn:
        row = conn.execute("SELECT media_path FROM records WHERE id=?", (record_id,)).fetchone()
    if not row or not Path(row["media_path"]).exists(): abort(404)
    return send_file(row["media_path"], conditional=True)


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Upload is too large"), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8765")))
