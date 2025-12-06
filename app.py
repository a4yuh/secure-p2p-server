"""
app.py – Peer registry + optional encrypted file relay (hybrid mode).

Role:
- /health       : simple health check
- /register     : register peer_code -> ip:port (+ optional public_key_pem)
- /resolve      : resolve peer_code -> ip:port (+ optional public_key_pem)
- /upload       : store encrypted file + encrypted AES key, return token
- /download/<t> : allow recipient to download encrypted file + encrypted key

Notes:
- Files are stored encrypted; server never sees plaintext.
- Metadata and uploads are kept in memory + local disk, suitable for small-scale use.
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import time
import secrets
import base64
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------------------
# Registry: peer_code -> ip:port (+ optional public_key_pem)
# ---------------------------------------------------------------------

# peer_registry structure:
# {
#   "123318148": {
#       "ip": "1.2.3.4",
#       "port": 5050,
#       "last_seen": 1733400000.0,
#       "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
#   },
#   ...
# }
peer_registry = {}

# ---------------------------------------------------------------------
# Upload storage: token -> metadata
# ---------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# In-memory mapping:
# {
#   token: {
#       "path": "/full/path/to/file",
#       "filename": "original_name.ext",
#       "encrypted_key_b64": "...",
#       "peer_code": "123 456 789",
#       "created_at": 1733400000.0
#   }
# }
uploads = {}

# Max upload size in bytes (default ~200 MB).
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 200 * 1024 * 1024))


# ---------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ---------------------------------------------------------------------
# Peer registry
# ---------------------------------------------------------------------

@app.route("/register", methods=["POST"])
def register():
    """
    Register a peer in the registry.

    Expected JSON:
    {
        "peer_code": "<digits-only>",
        "ip": "<ip>",
        "port": <int>,
        "public_key_pem": "-----BEGIN PUBLIC KEY-----..."   # optional
    }
    """
    data = request.get_json(silent=True) or {}

    peer_code = data.get("peer_code")
    ip = data.get("ip")
    port = data.get("port")
    public_key_pem = data.get("public_key_pem")  # may be None

    if not peer_code or not ip or port is None:
        print(f"[REGISTER] Invalid registration attempt: {data}")
        return jsonify({"error": "peer_code, ip and port are required"}), 400

    try:
        port = int(port)
    except (TypeError, ValueError):
        print(f"[REGISTER] Invalid port value in registration: {data}")
        return jsonify({"error": "port must be an integer"}), 400

    peer_registry[peer_code] = {
        "ip": ip,
        "port": port,
        "last_seen": time.time(),
        "public_key_pem": public_key_pem,
    }

    print(
        f"[REGISTER] {peer_code} -> {ip}:{port} "
        f"(public key present={bool(public_key_pem)})"
    )
    return jsonify({"status": "ok"}), 200


@app.route("/resolve/<peer_code>", methods=["GET"])
def resolve(peer_code):
    """
    Resolve a peer code to connection info.

    Returns JSON:
    {
        "ip": "...",
        "port": 5050,
        "public_key_pem": "-----BEGIN PUBLIC KEY-----..."   # or null
    }
    """
    entry = peer_registry.get(peer_code)
    if not entry:
        print(f"[RESOLVE] Peer code not found: {peer_code}")
        return jsonify({"error": "Not found"}), 404

    print(
        f"[RESOLVE] {peer_code} -> {entry['ip']}:{entry['port']} "
        f"(public key present={bool(entry.get('public_key_pem'))})"
    )

    return jsonify(
        {
            "ip": entry["ip"],
            "port": entry["port"],
            "public_key_pem": entry.get("public_key_pem"),
        }
    ), 200


# ---------------------------------------------------------------------
# Hybrid backup: upload encrypted file + encrypted AES key
# ---------------------------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload():
    """
    Upload an encrypted file + encrypted AES key.

    Expected multipart/form-data:
    - file: binary encrypted file (iv + ciphertext)
    - peer_code: intended recipient's peer code (string)
    - filename: original filename (string)
    - encrypted_key_b64: base64 of RSA-encrypted AES key (string)

    Returns:
    - 200 + {"token": "..."} on success
    """
    # Enforce size limit from Content-Length if present
    content_length = request.content_length
    if content_length is not None and content_length > MAX_UPLOAD_BYTES:
        return jsonify({"error": "File too large for this service"}), 413

    if "file" not in request.files:
        return jsonify({"error": "Missing file field"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    peer_code = request.form.get("peer_code")
    filename = request.form.get("filename", file.filename)
    encrypted_key_b64 = request.form.get("encrypted_key_b64")

    if not peer_code or not encrypted_key_b64:
        return jsonify({"error": "peer_code and encrypted_key_b64 are required"}), 400

    # Minimal sanity check on encrypted key length
    try:
        _ = base64.b64decode(encrypted_key_b64)
    except Exception:
        return jsonify({"error": "encrypted_key_b64 is not valid base64"}), 400

    safe_name = secure_filename(filename)
    token = secrets.token_urlsafe(16)
    stored_name = f"{token}.bin"
    stored_path = os.path.join(UPLOAD_DIR, stored_name)

    file.save(stored_path)

    uploads[token] = {
        "path": stored_path,
        "filename": safe_name or "file.bin",
        "encrypted_key_b64": encrypted_key_b64,
        "peer_code": peer_code,
        "created_at": time.time(),
    }

    print(f"[UPLOAD] token={token}, file={stored_path}, for peer_code={peer_code}")
    return jsonify({"token": token}), 200


# ---------------------------------------------------------------------
# Hybrid backup: download encrypted file + encrypted AES key
# ---------------------------------------------------------------------

@app.route("/download/<token>", methods=["GET"])
def download(token):
    """
    Download an encrypted file by token.

    Returns:
    - 200 + file as attachment
      with header 'X-Encrypted-Key' containing base64 RSA-encrypted AES key.
    - 404 if token not found.
    """
    meta = uploads.get(token)
    if not meta:
        print(f"[DOWNLOAD] Unknown token: {token}")
        return jsonify({"error": "Not found"}), 404

    file_path = meta["path"]
    filename = meta["filename"]
    encrypted_key_b64 = meta["encrypted_key_b64"]

    if not os.path.exists(file_path):
        print(f"[DOWNLOAD] File missing on disk for token: {token}")
        return jsonify({"error": "File missing"}), 410

    print(f"[DOWNLOAD] Serving token={token}, file={file_path}")

    # Remove from memory mapping (one-time download behaviour)
    uploads.pop(token, None)

    # Use send_file to stream response and attach encrypted key in header
    response = send_file(file_path, as_attachment=True, download_name=filename)
    response.headers["X-Encrypted-Key"] = encrypted_key_b64

    # Optional: delete file from disk after serving once
    try:
        os.remove(file_path)
    except OSError:
        pass

    return response


# ---------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"[STARTUP] Binding to 0.0.0.0 on port {port}")
    print("[STARTUP] Active routes:")
    for rule in app.url_map.iter_rules():
        print(f"  {rule}  ->  {','.join(sorted(rule.methods))}")

    app.run(host="0.0.0.0", port=port)