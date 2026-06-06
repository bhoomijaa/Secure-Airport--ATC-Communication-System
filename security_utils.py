# security_utils.py
import os
import json
import hashlib
import hmac
import time
import secrets
import struct
from cryptography.fernet import Fernet

# --- CONFIGURATION ---
KEY_ENV = "SHARED_SECRET_KEY"
DEFAULT_KEY_FILE = "shared.key"
NONCE_TTL = 60       # seconds to keep used nonces (server-side)
TIMESTAMP_SKEW = 15  # allowed clock skew in seconds

# --- Shared Fernet key loader ---
def _load_shared_key():
    key = os.environ.get(KEY_ENV)
    if key:
        return key.encode()
    if os.path.exists(DEFAULT_KEY_FILE):
        with open(DEFAULT_KEY_FILE, "rb") as f:
            return f.read().strip()
    # create and persist for local testing (do NOT commit generated file in real deployments)
    k = Fernet.generate_key()
    with open(DEFAULT_KEY_FILE, "wb") as f:
        f.write(k)
    return k

SHARED_SECRET_KEY = _load_shared_key()
cipher_suite = Fernet(SHARED_SECRET_KEY)

# --- Encryption helpers ---
def encrypt_message(data_dict):
    json_data = json.dumps(data_dict).encode('utf-8')
    return cipher_suite.encrypt(json_data)

def decrypt_message(encrypted_data):
    try:
        decrypted_json = cipher_suite.decrypt(encrypted_data).decode('utf-8')
        return json.loads(decrypted_json)
    except Exception:
        return None

# --- HMAC helpers ---
def generate_hmac_signature(message_bytes, secret_token):
    if isinstance(secret_token, str):
        secret_token = secret_token.encode('utf-8')
    return hmac.new(secret_token, message_bytes, hashlib.sha256).hexdigest()

def verify_hmac_signature(message_bytes, signature_hex, secret_token):
    expected = generate_hmac_signature(message_bytes, secret_token)
    return hmac.compare_digest(expected, signature_hex)

# --- Replay protection helpers (server-side in-memory) ---
USED_NONCES = {}  # {entity_id: {nonce: timestamp}}

def is_nonce_used(entity_id, nonce):
    now = time.time()
    # prune old entries
    for eid in list(USED_NONCES.keys()):
        USED_NONCES[eid] = {n: t for n, t in USED_NONCES[eid].items() if now - t < NONCE_TTL}
        if not USED_NONCES[eid]:
            del USED_NONCES[eid]
    if entity_id not in USED_NONCES:
        USED_NONCES[entity_id] = {}
    if nonce in USED_NONCES[entity_id]:
        return True
    USED_NONCES[entity_id][nonce] = now
    return False

def timestamp_fresh(ts):
    try:
        ts = int(ts)
    except Exception:
        return False
    now = int(time.time())
    return abs(now - ts) <= TIMESTAMP_SKEW

# --- Server signing helpers (semantic wrappers) ---
def sign_server_message(message_dict, airport_secret):
    payload_bytes = json.dumps(message_dict, sort_keys=True).encode('utf-8')
    return generate_hmac_signature(payload_bytes, airport_secret)

def verify_server_message(message_dict, signature_hex, airport_secret):
    verify_payload = {k: message_dict[k] for k in sorted(message_dict) if k != "signature"}
    payload_bytes = json.dumps(verify_payload, sort_keys=True).encode('utf-8')
    return verify_hmac_signature(payload_bytes, signature_hex, airport_secret)

# --- Framing helpers (length-prefixed) ---
def send_framed(sock, data_bytes):
    length = struct.pack("!I", len(data_bytes))
    sock.sendall(length + data_bytes)

def recv_framed(sock):
    header = b""
    try:
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return None
            header += chunk
        length = struct.unpack("!I", header)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(min(4096, length - len(data)))
            if not chunk:
                return None
            data += chunk
        return data
    except Exception:
        return None