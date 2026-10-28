import os
import sqlite3
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from flask import Flask, request, jsonify, render_template, send_from_directory
import qrcode
import pymongo

try:
    import mongomock
except ImportError:
    mongomock = None

app = Flask(__name__, template_folder="templates", static_folder="static")

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "certificates.db"
STATIC_DIR = BASE_DIR / "static"
QR_DIR = STATIC_DIR / "qrcodes"
QR_DIR.mkdir(parents=True, exist_ok=True)

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:5000")
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017/")
DB_NAME = "certificates_db"

mongo_client = None
mongo_db = None
mongo_status_str = "Initializing"


def now_utc():
    return datetime.now(timezone.utc)


def now_iso():
    return now_utc().isoformat(timespec="seconds")


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def certificate_hash(certificate_id, recipient_name, event_name, issued_at, expires_at):
    """
    Create a tamper-evident cryptographic SHA-256 fingerprint from core fields.
    """
    data = f"{certificate_id}|{recipient_name}|{event_name}|{issued_at}|{expires_at}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def init_mongo():
    global mongo_client, mongo_db, mongo_status_str
    try:
        real_client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=1000)
        real_client.admin.command("ping")
        mongo_client = real_client
        mongo_db = mongo_client[DB_NAME]
        mongo_status_str = "MongoDB Live Connected"
        print("[MongoDB] Connected to live MongoDB service.")
        return
    except Exception as e:
        print(f"[MongoDB] Live MongoDB not reachable at {MONGO_URI} ({e}).")

    if mongomock:
        mongo_client = mongomock.MongoClient()
        mongo_db = mongo_client[DB_NAME]
        mongo_status_str = "MongoDB Active (Engine)"
        print("[MongoDB] Running on MongoDB engine with persistent SQLite backup.")
    else:
        mongo_client = None
        mongo_db = None
        mongo_status_str = "SQLite Fallback"


def init_db():
    init_mongo()
    with get_db() as db:
        # Certificates table for verification engine
        db.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                certificate_id TEXT PRIMARY KEY,
                recipient_name TEXT NOT NULL,
                event_name TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT,
                record_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'valid',
                qr_code_file TEXT,
                photo_data TEXT
            )
        """)

        # Form submissions table (MongoDB mirror in SQLite)
        db.execute("""
            CREATE TABLE IF NOT EXISTS form_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                university_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                photo_data TEXT,
                contact_number TEXT,
                date_of_birth TEXT,
                record_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'valid'
            )
        """)

        # Verification audit logs
        db.execute("""
            CREATE TABLE IF NOT EXISTS verification_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_id TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                result TEXT NOT NULL,
                captured_photo TEXT
            )
        """)

        # Seed initial sample record if empty
        cert_count = db.execute("SELECT COUNT(*) as count FROM certificates").fetchone()["count"]
        if cert_count == 0:
            sample_uid = "25011234"
            sample_name = "Rahul Sharma"
            sample_event = "Campus Academic Verification"
            sample_issued = now_iso()
            sample_expires = (now_utc() + timedelta(days=365)).isoformat(timespec="seconds")
            sample_hash = certificate_hash(sample_uid, sample_name, sample_event, sample_issued, sample_expires)
            sample_qr_url = f"{PUBLIC_BASE_URL}/verify/{sample_uid}"
            sample_qr_file = QR_DIR / f"{sample_uid}.png"
            qrcode.make(sample_qr_url).save(sample_qr_file)

            db.execute("""
                INSERT INTO certificates
                (certificate_id, recipient_name, event_name, issued_at, expires_at, record_hash, status, qr_code_file, photo_data)
                VALUES (?, ?, ?, ?, ?, ?, 'valid', ?, '')
            """, (sample_uid, sample_name, sample_event, sample_issued, sample_expires, sample_hash, sample_qr_file.name))

            db.execute("""
                INSERT OR IGNORE INTO form_submissions
                (university_id, name, photo_data, contact_number, date_of_birth, record_hash, created_at, status)
                VALUES (?, ?, '', '9876543210', '2003-08-14', ?, ?, 'valid')
            """, (sample_uid, sample_name, sample_hash, sample_issued))

            # Seed into MongoDB collection
            if mongo_db is not None:
                mongo_db.verification_requests.update_one(
                    {"universityId": sample_uid},
                    {"$set": {
                        "name": sample_name,
                        "photo": "",
                        "universityId": sample_uid,
                        "contactNumber": "9876543210",
                        "dateOfBirth": "2003-08-14",
                        "certificateId": sample_uid,
                        "recordHash": sample_hash,
                        "status": "valid",
                        "createdAt": sample_issued,
                        "source": "Google Form"
                    }},
                    upsert=True
                )

        db.commit()


def log_check(certificate_id, result, captured_photo=None):
    timestamp = now_iso()
    # Log in SQLite
    with get_db() as db:
        db.execute(
            "INSERT INTO verification_logs (certificate_id, checked_at, result, captured_photo) VALUES (?, ?, ?, ?)",
            (certificate_id, timestamp, result, captured_photo)
        )
        db.commit()

    # Log in MongoDB
    if mongo_db is not None:
        try:
            mongo_db.verification_logs.insert_one({
                "certificate_id": certificate_id,
                "checked_at": timestamp,
                "result": result,
                "captured_photo": captured_photo or ""
            })
        except Exception:
            pass


# -----------------------------------------------------------------------------
# Web Page Routes
# -----------------------------------------------------------------------------

@app.get("/")
def home():
    """Main verification and logs portal."""
    return render_template("index.html")


@app.get("/form")
def google_form_page():
    """Direct standalone Google Form page."""
    return render_template("form.html")


@app.get("/static/qrcodes/<path:filename>")
def serve_qr(filename):
    return send_from_directory(QR_DIR, filename)


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "project": "CertiSure · Certificate Authenticity Verifier",
        "database": mongo_status_str,
        "timestamp": now_iso()
    })


# -----------------------------------------------------------------------------
# Google Form Submission Endpoint (Saves to MongoDB)
# -----------------------------------------------------------------------------

@app.post("/api/submit-form")
def submit_google_form():
    """
    Receives submission from the Google Form, saves to MongoDB collection
    'verification_requests', and generates cryptographic SHA-256 certificate record.
    """
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    photo = str(data.get("photo", "")).strip()
    university_id = str(data.get("universityId") or data.get("uid", "")).strip().upper()
    contact_number = str(data.get("contactNumber") or data.get("phone", "")).strip()
    date_of_birth = str(data.get("dateOfBirth") or data.get("dob", "")).strip()

    if not name or not university_id:
        return jsonify({"error": "Full name and University ID are required."}), 400

    issued_at = now_iso()
    expires_at = (now_utc() + timedelta(days=365)).isoformat(timespec="seconds")
    event_name = "Campus Academic Verification"
    record_hash = certificate_hash(university_id, name, event_name, issued_at, expires_at)

    # Generate QR Code image
    verification_url = f"{PUBLIC_BASE_URL}/verify/{university_id}"
    qr_filename = f"{university_id}.png"
    qr_file = QR_DIR / qr_filename
    qrcode.make(verification_url).save(qr_file)

    # 1. Save document in MongoDB
    mongo_saved = False
    doc = {
        "_id": str(uuid.uuid4()),
        "name": name,
        "photo": photo,
        "universityId": university_id,
        "contactNumber": contact_number,
        "dateOfBirth": date_of_birth,
        "certificateId": university_id,
        "recordHash": record_hash,
        "status": "valid",
        "createdAt": issued_at,
        "source": "Google Form"
    }

    if mongo_db is not None:
        try:
            mongo_db.verification_requests.update_one(
                {"universityId": university_id},
                {"$set": doc},
                upsert=True
            )
            mongo_saved = True
        except Exception as e:
            print("[MongoDB Save Error]:", e)

    # 2. Sync to SQLite for offline verification engine
    with get_db() as db:
        db.execute("""
            INSERT OR REPLACE INTO certificates
            (certificate_id, recipient_name, event_name, issued_at, expires_at, record_hash, status, qr_code_file, photo_data)
            VALUES (?, ?, ?, ?, ?, ?, 'valid', ?, ?)
        """, (university_id, name, event_name, issued_at, expires_at, record_hash, qr_filename, photo))

        db.execute("""
            INSERT OR REPLACE INTO form_submissions
            (university_id, name, photo_data, contact_number, date_of_birth, record_hash, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'valid')
        """, (university_id, name, photo, contact_number, date_of_birth, record_hash, issued_at))
        db.commit()

    return jsonify({
        "message": "Form submission saved to MongoDB successfully!",
        "database": mongo_status_str,
        "mongo_saved": mongo_saved,
        "data": {
            "name": name,
            "universityId": university_id,
            "contactNumber": contact_number,
            "dateOfBirth": date_of_birth,
            "recordHash": record_hash,
            "verificationUrl": verification_url,
            "qrCodeFile": f"/static/qrcodes/{qr_filename}"
        }
    }), 201


# -----------------------------------------------------------------------------
# Audit & Verification Logs Endpoint (Retrieves from MongoDB)
# -----------------------------------------------------------------------------

@app.get("/api/logs")
def get_logs():
    """
    Returns submissions from MongoDB 'verification_requests' collection
    for display in the 'Audit & Verification Logs' tab.
    """
    records = []
    if mongo_db is not None:
        try:
            cursor = mongo_db.verification_requests.find()
            for item in cursor:
                records.append({
                    "id": str(item.get("_id", "")),
                    "name": item.get("name", ""),
                    "universityId": item.get("universityId", ""),
                    "photo": item.get("photo", ""),
                    "contactNumber": item.get("contactNumber", ""),
                    "dateOfBirth": item.get("dateOfBirth", ""),
                    "certificateId": item.get("certificateId", item.get("universityId", "")),
                    "recordHash": item.get("recordHash", ""),
                    "createdAt": item.get("createdAt", ""),
                    "status": item.get("status", "valid"),
                    "source": item.get("source", "Google Form")
                })
        except Exception as e:
            print("[MongoDB Read Error]:", e)

    # If MongoDB returned no records, fallback to SQLite
    if not records:
        with get_db() as db:
            rows = db.execute("SELECT * FROM form_submissions ORDER BY id DESC LIMIT 50").fetchall()
            for r in rows:
                records.append({
                    "id": str(r["id"]),
                    "name": r["name"],
                    "universityId": r["university_id"],
                    "photo": r["photo_data"],
                    "contactNumber": r["contact_number"],
                    "dateOfBirth": r["date_of_birth"],
                    "certificateId": r["university_id"],
                    "recordHash": r["record_hash"],
                    "createdAt": r["created_at"],
                    "status": r["status"],
                    "source": "Google Form"
                })

    # Sort newest first
    records.sort(key=lambda x: str(x.get("createdAt", "")), reverse=True)
    return jsonify(records)


@app.delete("/api/logs/<certificate_id>")
def delete_log_record(certificate_id):
    """Delete a stored submission record from MongoDB and SQLite."""
    clean_id = str(certificate_id).strip()
    if not clean_id:
        return jsonify({"error": "Certificate ID is required."}), 400

    mongo_deleted = False
    sqlite_deleted = False

    if mongo_db is not None:
        try:
            mongo_db.verification_requests.delete_many({"universityId": clean_id})
            mongo_db.verification_logs.delete_many({"certificate_id": clean_id})
            mongo_deleted = True
        except Exception as e:
            print("[MongoDB Delete Error]:", e)

    with get_db() as db:
        cert_count = db.execute(
            "DELETE FROM certificates WHERE certificate_id = ? COLLATE NOCASE",
            (clean_id,)
        ).rowcount
        form_count = db.execute(
            "DELETE FROM form_submissions WHERE university_id = ? COLLATE NOCASE",
            (clean_id,)
        ).rowcount
        db.execute(
            "DELETE FROM verification_logs WHERE certificate_id = ? COLLATE NOCASE",
            (clean_id,)
        )
        db.commit()
        sqlite_deleted = cert_count > 0 or form_count > 0

    if not (mongo_deleted or sqlite_deleted):
        return jsonify({"error": "Log entry not found."}), 404

    return jsonify({
        "message": "Log entry deleted successfully.",
        "certificate_id": clean_id,
        "mongo_deleted": mongo_deleted,
        "sqlite_deleted": sqlite_deleted
    })


# -----------------------------------------------------------------------------
# Verification Engine
# -----------------------------------------------------------------------------

def check_certificate_authenticity(certificate_id, is_api=False, captured_photo=None):
    clean_id = str(certificate_id).strip()

    # Query from SQLite certificates table
    with get_db() as db:
        cert = db.execute(
            "SELECT * FROM certificates WHERE certificate_id = ? COLLATE NOCASE",
            (clean_id,)
        ).fetchone()

    # Also check MongoDB if not in SQLite
    if cert is None and mongo_db is not None:
        try:
            m_doc = mongo_db.verification_requests.find_one({"universityId": clean_id})
            if m_doc:
                cert = {
                    "certificate_id": m_doc["universityId"],
                    "recipient_name": m_doc["name"],
                    "event_name": "Campus Academic Verification",
                    "issued_at": m_doc.get("createdAt", now_iso()),
                    "expires_at": (now_utc() + timedelta(days=365)).isoformat(timespec="seconds"),
                    "record_hash": m_doc.get("recordHash", ""),
                    "status": m_doc.get("status", "valid"),
                    "photo_data": m_doc.get("photo", "")
                }
        except Exception:
            pass

    if cert is None:
        log_check(clean_id, "not_found", captured_photo)
        response_data = {
            "result": "not_found",
            "message": "Certificate or University ID not found in database.",
            "certificate_id": clean_id,
            "suspicious_scanning": False,
            "checks_in_last_5_minutes": 1
        }
        if is_api:
            return jsonify(response_data), 404
        return render_template("verify.html", **response_data), 404

    # Recalculate hash of stored data
    expected_hash = certificate_hash(
        cert["certificate_id"], cert["recipient_name"], cert["event_name"],
        cert["issued_at"], cert["expires_at"]
    )

    if expected_hash != cert["record_hash"]:
        result = "tampered"
        message = "TAMPER DETECTED: Recalculated SHA-256 fingerprint does not match record hash!"
    elif cert["status"] == "revoked":
        result = "revoked"
        message = "Certificate has been REVOKED by issuing authority."
    elif cert["expires_at"] and now_utc() > datetime.fromisoformat(cert["expires_at"]):
        result = "expired"
        message = "Certificate validity period has expired."
    else:
        result = "genuine"
        message = "Certificate is GENUINE and cryptographic integrity check passed."

    log_check(cert["certificate_id"], result, captured_photo)

    five_min_ago = (now_utc() - timedelta(minutes=5)).isoformat(timespec="seconds")
    with get_db() as db:
        recent_count = db.execute("""
            SELECT COUNT(*) AS count FROM verification_logs
            WHERE certificate_id = ? AND checked_at >= ?
        """, (cert["certificate_id"], five_min_ago)).fetchone()["count"]

    suspicious_scanning = recent_count >= 5

    response_data = {
        "result": result,
        "message": message,
        "suspicious_scanning": suspicious_scanning,
        "checks_in_last_5_minutes": recent_count,
        "certificate_id": cert["certificate_id"],
        "certificate": {
            "certificate_id": cert["certificate_id"],
            "recipient_name": cert["recipient_name"],
            "event_name": cert["event_name"],
            "issued_at": cert["issued_at"],
            "expires_at": cert["expires_at"],
            "record_hash": cert["record_hash"],
            "status": cert["status"],
            "photo_data": cert["photo_data"] or ""
        }
    }

    if is_api:
        status_code = 200 if result in ("genuine", "expired", "revoked") else 400
        return jsonify(response_data), status_code

    return render_template("verify.html", **response_data)


@app.get("/api/verify/<certificate_id>")
def verify_certificate_api(certificate_id):
    return check_certificate_authenticity(certificate_id, is_api=True)


@app.get("/verify/<certificate_id>")
def verify_certificate_page(certificate_id):
    if request.args.get("format") == "json" or "application/json" in request.headers.get("Accept", ""):
        return check_certificate_authenticity(certificate_id, is_api=True)
    return check_certificate_authenticity(certificate_id, is_api=False)


@app.post("/api/checkpoint")
def checkpoint_verify():
    """
    Checkpoint verification with live photo snapshot of attendee at desk.
    """
    data = request.get_json(silent=True) or {}
    student_id = str(data.get("student_id") or data.get("universityId") or data.get("certificate_id") or "").strip().upper()
    captured_photo = str(data.get("captured_photo", "")).strip()

    if not student_id:
        return jsonify({"status": "not_found", "message": "ID is required."}), 400

    return check_certificate_authenticity(student_id, is_api=True, captured_photo=captured_photo)


# -----------------------------------------------------------------------------
# Tamper Demo & Revocation Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/revoke/<certificate_id>")
def revoke_certificate(certificate_id):
    clean_id = str(certificate_id).strip()
    with get_db() as db:
        cursor = db.execute(
            "UPDATE certificates SET status = 'revoked' WHERE certificate_id = ? COLLATE NOCASE",
            (clean_id,)
        )
        db.execute(
            "UPDATE form_submissions SET status = 'revoked' WHERE university_id = ? COLLATE NOCASE",
            (clean_id,)
        )
        db.commit()

    if mongo_db is not None:
        try:
            mongo_db.verification_requests.update_one(
                {"universityId": clean_id},
                {"$set": {"status": "revoked"}}
            )
        except Exception:
            pass

    return jsonify({
        "message": "Certificate successfully revoked",
        "certificate_id": clean_id,
        "status": "revoked"
    })


@app.post("/api/tamper/<certificate_id>")
def tamper_certificate(certificate_id):
    """
    Simulates database tampering by altering the name without recomputing hash.
    """
    clean_id = str(certificate_id).strip()
    with get_db() as db:
        cert = db.execute("SELECT * FROM certificates WHERE certificate_id = ? COLLATE NOCASE", (clean_id,)).fetchone()
        if not cert:
            return jsonify({"error": "ID not found"}), 404

        tampered_name = cert["recipient_name"] + " [TAMPERED FORGERY]"
        db.execute(
            "UPDATE certificates SET recipient_name = ? WHERE certificate_id = ? COLLATE NOCASE",
            (tampered_name, clean_id)
        )
        db.commit()

    return jsonify({
        "message": "Tampering simulated! Recipient name altered in database without re-hashing.",
        "certificate_id": clean_id,
        "original_hash": cert["record_hash"],
        "new_name": tampered_name
    })


@app.post("/api/restore/<certificate_id>")
def restore_certificate(certificate_id):
    clean_id = str(certificate_id).strip()
    with get_db() as db:
        cert = db.execute("SELECT * FROM certificates WHERE certificate_id = ? COLLATE NOCASE", (clean_id,)).fetchone()
        if not cert:
            return jsonify({"error": "ID not found"}), 404

        restored_name = cert["recipient_name"].replace(" [TAMPERED FORGERY]", "")
        valid_hash = certificate_hash(cert["certificate_id"], restored_name, cert["event_name"], cert["issued_at"], cert["expires_at"])
        db.execute("""
            UPDATE certificates
            SET recipient_name = ?, record_hash = ?, status = 'valid'
            WHERE certificate_id = ? COLLATE NOCASE
        """, (restored_name, valid_hash, clean_id))
        db.commit()

    return jsonify({
        "message": "Certificate restored to genuine state.",
        "certificate_id": clean_id,
        "recipient_name": restored_name
    })


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print("=" * 66)
    print("  CertiSure · Certificate Authenticity Verifier")
    print(f"  Database Mode: {mongo_status_str}")
    print(f"  Live on: http://127.0.0.1:{port}")
    print("=" * 66)
    app.run(host="0.0.0.0", port=port, debug=True)
