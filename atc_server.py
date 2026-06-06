# atc_server.py
import socket
import threading
import time
import db_logger
import security_utils
import json
import os
import random
from queue import PriorityQueue

HOST = '127.0.0.1'
PORT = 65432

# Resources & capacities
RUNWAY_CAPACITY = 2
GATE_CAPACITY = 3

runway_sem = threading.Semaphore(RUNWAY_CAPACITY)
gate_sem = threading.Semaphore(GATE_CAPACITY)
resource_cond = threading.Condition()

# Rate limiting & temp blacklist (unchanged)
BLACKLIST = {}
CLIENT_REQUEST_HISTORY = {}
RATE_LIMIT_THRESHOLD = 50
RATE_LIMIT_WINDOW = 2.0
TEMP_BAN_SECONDS = 30

# Client registry: airplane_id -> (conn, addr, last_seen, subscribed_flag)
CLIENTS = {}
CLIENTS_LOCK = threading.Lock()

# Request queue: priority queue, (priority, enq_time, seq, payload, conn)
REQUEST_QUEUE = PriorityQueue()
REQUEST_SEQ = 0
QUEUE_LOCK = threading.Lock()

# Secrets loading (file-based fallback to env)
SECRETS_DIR = os.path.join(os.path.dirname(__file__), "secrets")
AIRPORT_SECRET_FILE = os.path.join(SECRETS_DIR, "airport_secret.json")
AIRPLANE_SECRETS_FILE = os.path.join(SECRETS_DIR, "airplane_secrets.json")

def load_airport_secret_from_file():
    try:
        with open(AIRPORT_SECRET_FILE, "r") as f:
            data = json.load(f)
            s = data.get("airport_secret")
            if s:
                return s
    except Exception:
        pass
    return os.environ.get("AIRPORT_SECRET", "DEFAULT_AIRPORT_SECRET_SIM")

def load_airplane_secrets_from_file():
    try:
        with open(AIRPLANE_SECRETS_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    s = os.environ.get("AIRPLANE_SECRETS")
    if s:
        try:
            return json.loads(s)
        except Exception:
            pass
    return {}

AIRPORT_SECRET = load_airport_secret_from_file()
AIRPLANE_SECRETS = load_airplane_secrets_from_file()

# Weather / severity
weather_state = {"visibility": 10.0, "wind_speed": 5.0, "severity": 0}
weather_lock = threading.Lock()
WEATHER_UPDATE_INTERVAL = 10
HOLD_SEVERITY_THRESHOLD = 2  # severity >= threshold => non-emergency holds

# Stats
stats_lock = threading.Lock()
stats = {"processed": 0, "emergencies": 0, "avg_wait": 0.0}

# Helpers for client registry
def register_client(airplane_id, conn, addr):
    with CLIENTS_LOCK:
        # store subscribed flag as False by default
        CLIENTS[airplane_id] = (conn, addr, time.time(), False)
        print(f"[CLIENTS] Registered {airplane_id} -> {addr} (subscribed=False)")

def unregister_client_by_conn(conn):
    with CLIENTS_LOCK:
        for aid, (c, addr, ts, sub) in list(CLIENTS.items()):
            if c == conn:
                del CLIENTS[aid]
                print(f"[CLIENTS] Unregistered {aid}")
                break

def set_client_subscription(airplane_id, subscribed: bool):
    with CLIENTS_LOCK:
        info = CLIENTS.get(airplane_id)
        if not info:
            return False
        conn, addr, ts, _ = info
        CLIENTS[airplane_id] = (conn, addr, ts, subscribed)
        print(f"[CLIENTS] Set subscription {airplane_id} -> {subscribed}")
        return True

def send_signed_message_to_client(conn, payload_dict):
    sig = security_utils.sign_server_message(payload_dict, AIRPORT_SECRET)
    message = dict(payload_dict)
    message["signature"] = sig
    encrypted = security_utils.encrypt_message(message)
    try:
        security_utils.send_framed(conn, encrypted)
        return True
    except Exception as e:
        print(f"[ERROR] sending signed message: {e}")
        return False

# Weather broadcast: only to subscribed clients
def broadcast_weather():
    while True:
        with weather_lock:
            weather_state['visibility'] = round(random.uniform(0.5, 15.0), 1)
            weather_state['wind_speed'] = round(random.uniform(0.0, 30.0), 1)
            if weather_state['visibility'] < 2.0 or weather_state['wind_speed'] > 20.0:
                weather_state['severity'] = 2
            elif weather_state['visibility'] < 5.0 or weather_state['wind_speed'] > 12.0:
                weather_state['severity'] = 1
            else:
                weather_state['severity'] = 0
            ts = int(time.time())
            payload = {
                "type": "WEATHER_UPDATE",
                "timestamp": ts,
                "nonce": os.urandom(8).hex(),
                "weather": dict(weather_state)
            }
            db_logger.log_event("ATC", "WEATHER_BROADCAST", json.dumps(weather_state), "BROADCAST")

        # send only to clients with subscription True
        with CLIENTS_LOCK:
            for aid, (conn, addr, last_seen, subscribed) in list(CLIENTS.items()):
                if not subscribed:
                    continue
                try:
                    send_signed_message_to_client(conn, payload)
                except Exception as e:
                    print(f"[ERROR] broadcast to {aid} failed: {e}")
        time.sleep(WEATHER_UPDATE_INTERVAL)

# Dispatcher and admin_cli unchanged except they rely on CLIENTS structure (no broadcast changes needed)
# (Dispatcher code omitted here for brevity — keep your previous dispatcher_loop, unchanged,
# but make sure to use the new CLIENTS tuple structure where needed.)

# For clarity, copy dispatcher_loop and admin_cli from your previous server code and keep them unchanged,
# except any references to CLIENTS must unpack 4-tuple (conn,addr,ts,subscribed).

# Rate-limiter and blacklist helpers
def is_blacklisted(ip):
    expiry = BLACKLIST.get(ip)
    if not expiry:
        return False
    if time.time() > expiry:
        del BLACKLIST[ip]
        return False
    return True

def record_request(ip):
    now = time.time()
    arr = CLIENT_REQUEST_HISTORY.setdefault(ip, [])
    CLIENT_REQUEST_HISTORY[ip] = [t for t in arr if now - t < RATE_LIMIT_WINDOW]
    CLIENT_REQUEST_HISTORY[ip].append(now)
    return len(CLIENT_REQUEST_HISTORY[ip])

# Client connection handler (handles SUBSCRIBE/UNSUBSCRIBE messages)
def handle_client(conn, addr):
    global REQUEST_SEQ
    ip = addr[0]
    print(f"[NEW CONNECTION] {addr} connected.")
    authenticated_airplane = None
    try:
        while True:
            if is_blacklisted(ip):
                print(f"[BLOCKED] Temporary banned IP: {ip}")
                conn.close()
                return

            data = security_utils.recv_framed(conn)
            if not data:
                break

            count = record_request(ip)
            if count > RATE_LIMIT_THRESHOLD:
                BLACKLIST[ip] = time.time() + TEMP_BAN_SECONDS
                db_logger.log_event(ip, "ATTACK_SIMULATION", f"Rate limit exceeded: {count}", "TEMP_BANNED")
                conn.close()
                return

            request = security_utils.decrypt_message(data)
            if not request:
                db_logger.log_event(ip, "ERROR", "Failed to decrypt message", "IGNORED")
                continue

            airplane_id = request.get('id')
            signature = request.get('signature')
            msg_type = request.get('type')
            nonce = request.get('nonce')
            timestamp = request.get('timestamp')

            if not (airplane_id and signature and msg_type and nonce and timestamp):
                db_logger.log_event(ip, "ERROR", f"Malformed request: {request}", "REJECTED")
                continue

            if not security_utils.timestamp_fresh(timestamp):
                db_logger.log_event(airplane_id, "ATTACK_SIMULATION", "Stale timestamp", "REJECTED")
                continue

            if security_utils.is_nonce_used(airplane_id, nonce):
                db_logger.log_event(airplane_id, "ATTACK_SIMULATION", "Nonce reuse", "REJECTED")
                continue

            secret = AIRPLANE_SECRETS.get(airplane_id)
            if not secret:
                db_logger.log_event(airplane_id, "ERROR", "Unknown airplane id", "REJECTED")
                continue

            verify_payload = {k: request[k] for k in sorted(request) if k != "signature"}
            payload_bytes = json.dumps(verify_payload, sort_keys=True).encode('utf-8')
            if not security_utils.verify_hmac_signature(payload_bytes, signature, secret):
                db_logger.log_event(airplane_id, "ATTACK_SIMULATION", "Invalid HMAC signature", "REJECTED")
                continue

            # Register client once authenticated
            if authenticated_airplane is None:
                authenticated_airplane = airplane_id
                # new register sets subscribed=False by default
                register_client(airplane_id, conn, addr)

            # Handle subscription messages explicitly
            if msg_type == "SUBSCRIBE_WEATHER":
                set_client_subscription(airplane_id, True)
                db_logger.log_event(airplane_id, "SUBSCRIBE", "Weather subscription enabled", "SUBSCRIBED")
                payload = {"type": "ACK", "timestamp": int(time.time()), "nonce": os.urandom(8).hex(), "msg": "Subscribed to weather updates"}
                send_signed_message_to_client(conn, payload)
                continue
            if msg_type == "UNSUBSCRIBE_WEATHER":
                set_client_subscription(airplane_id, False)
                db_logger.log_event(airplane_id, "UNSUBSCRIBE", "Weather subscription disabled", "UNSUBSCRIBED")
                payload = {"type": "ACK", "timestamp": int(time.time()), "nonce": os.urandom(8).hex(), "msg": "Unsubscribed from weather updates"}
                send_signed_message_to_client(conn, payload)
                continue

            # Existing handlers (CHECK_WEATHER, ATC_MESSAGE, REQUEST_* etc.)
            if msg_type == "CHECK_WEATHER":
                with weather_lock:
                    payload = {"type": "WEATHER_REPLY", "timestamp": int(time.time()), "nonce": os.urandom(8).hex(), "weather": dict(weather_state)}
                send_signed_message_to_client(conn, payload)
                db_logger.log_event(airplane_id, "WEATHER_CHECK", "Sent weather", "SENT")
                continue

            if msg_type == "ATC_MESSAGE":
                db_logger.log_event(airplane_id, "MSG_FROM_PLANE", request.get("msg", ""), "RECEIVED")
                payload = {"type": "ACK", "timestamp": int(time.time()), "nonce": os.urandom(8).hex(), "msg": "ATC received your message."}
                send_signed_message_to_client(conn, payload)
                continue

            # Enqueue landing/takeoff/gate requests for dispatcher
            if msg_type in ("REQUEST_LANDING", "REQUEST_TAKEOFF", "REQUEST_GATE", "EMERGENCY"):
                emergency_flag = request.get('emergency', False) or (msg_type == "EMERGENCY")
                global_priority = 0 if emergency_flag else 1
                with QUEUE_LOCK:
                    REQUEST_SEQ += 1
                    req_pl = dict(request)
                    req_pl['enq_ts'] = time.time()
                    req_pl['emergency'] = emergency_flag
                    REQUEST_QUEUE.put((global_priority, req_pl['enq_ts'], REQUEST_SEQ, req_pl, conn))
                db_logger.log_event(airplane_id, "ENQUEUED", msg_type, "ENQUEUED")
                with resource_cond:
                    resource_cond.notify_all()
                continue

            # Unknown types -> ack
            db_logger.log_event(airplane_id, "UNKNOWN", msg_type, "IGNORED")
            payload = {"type": "ACK", "timestamp": int(time.time()), "nonce": os.urandom(8).hex(), "msg": f"ATC: Unknown request type {msg_type}"}
            send_signed_message_to_client(conn, payload)

    except Exception as e:
        print(f"[ERROR] Exception handling client {addr}: {e}")
    finally:
        try:
            unregister_client_by_conn(conn)
            conn.close()
        except Exception:
            pass

# Dispatcher and admin CLI functions from previous version should be included here unchanged.
# Make sure dispatcher_loop uses CLIENTS unpacking with 4 elements where needed.

def dispatcher_loop():
    # (Copy your dispatcher_loop implementation from previous server; it will work with new CLIENTS structure.)
    # For convenience, here's a minimal working version that reuses the allocation logic:
    global REQUEST_SEQ
    while True:
        try:
            item = REQUEST_QUEUE.get()
        except Exception:
            time.sleep(0.5)
            continue

        priority, enq_time, seq, request_payload, conn = item
        airplane_id = request_payload.get("id")
        req_type = request_payload.get("type")
        is_emergency = request_payload.get("emergency", False)

        with weather_lock:
            severity = weather_state['severity']

        if req_type == "REQUEST_LANDING" and (severity >= HOLD_SEVERITY_THRESHOLD) and not is_emergency:
            db_logger.log_event(airplane_id, "HOLD", "Weather severe - holding", "HELD")
            time.sleep(2)
            with QUEUE_LOCK:
                REQUEST_SEQ += 1
                REQUEST_QUEUE.put((priority, time.time(), REQUEST_SEQ, request_payload, conn))
            continue

        got_runway = runway_sem.acquire(timeout=10)
        if not got_runway:
            with QUEUE_LOCK:
                REQUEST_SEQ += 1
                REQUEST_QUEUE.put((priority, time.time(), REQUEST_SEQ, request_payload, conn))
            continue

        got_gate = gate_sem.acquire(timeout=8)
        assigned_gate = None
        if got_gate:
            assigned_gate = f"GATE-{random.randint(1,20)}"
        assigned_runway = f"RWY-{random.randint(1,8)}"

        resp_payload = {
            "type": "RUNWAY_GATE_ALLOTMENT",
            "timestamp": int(time.time()),
            "nonce": os.urandom(8).hex(),
            "runway": assigned_runway,
            "gate": assigned_gate,
            "msg": f"Assigned runway {assigned_runway}" + (f" and gate {assigned_gate}" if assigned_gate else "")
        }

        try:
            send_signed_message_to_client(conn, resp_payload)
            db_logger.log_event(airplane_id, "ALLOTMENT", resp_payload.get("msg"), "SENT")
        except Exception as e:
            runway_sem.release()
            if got_gate:
                gate_sem.release()
            continue

        time.sleep(2)
        runway_sem.release()

        with stats_lock:
            stats['processed'] += 1
            if is_emergency:
                stats['emergencies'] += 1

        if got_gate:
            def release_gate_after_delay(gate_sem, delay=5):
                time.sleep(delay)
                gate_sem.release()
            t = threading.Thread(target=release_gate_after_delay, args=(gate_sem, random.randint(4,8)), daemon=True)
            t.start()

# Admin CLI unchanged (reuse previous admin_cli code).

def admin_cli():
    help_text = (
        "ATC Admin CLI commands:\n"
        "  help                     - show this\n"
        "  list                     - list connected clients\n"
        "  status                   - show resource & queue status\n"
        "  send <AIRPLANE_ID> <MSG> - send an arbitrary message to a plane\n"
        "  queue                    - show request queue size\n  exit                     - shut down server\n"
    )
    print(help_text)
    while True:
        try:
            cmd = input("ATC> ").strip()
        except EOFError:
            break
        if not cmd:
            continue
        if cmd == "help":
            print(help_text)
        elif cmd == "list":
            with CLIENTS_LOCK:
                for aid, (conn, addr, ts, sub) in CLIENTS.items():
                    print(f"{aid} -> {addr} last_seen={time.ctime(ts)} subscribed={sub}")
        elif cmd.startswith("send "):
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                print("Usage: send <AIRPLANE_ID> <MSG>")
                continue
            aid = parts[1]
            msg = parts[2]
            with CLIENTS_LOCK:
                info = CLIENTS.get(aid)
            if not info:
                print("No such connected client.")
                continue
            conn, addr, ts, sub = info
            payload = {"type": "ATC_MESSAGE", "timestamp": int(time.time()), "nonce": os.urandom(8).hex(), "msg": msg}
            send_signed_message_to_client(conn, payload)
            db_logger.log_event("ATC", "MANUAL_SEND", f"{aid}:{msg}", "SENT")
            print("Message sent.")
        elif cmd == "status":
            with CLIENTS_LOCK:
                ccount = len(CLIENTS)
            qsize = REQUEST_QUEUE.qsize()
            print(f"Clients connected: {ccount}  Queue size: {qsize}")
        elif cmd == "queue":
            print("Queue size:", REQUEST_QUEUE.qsize())
        elif cmd == "exit":
            print("Exiting admin CLI (server must be ctrl-c'd to stop).")
            break
        else:
            print("Unknown command; type 'help'.")

# Server startup
def start_server():
    db_logger.init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[STARTING] ATC Server listening on {HOST}:{PORT}")

    wb = threading.Thread(target=broadcast_weather, daemon=True)
    wb.start()

    disp = threading.Thread(target=dispatcher_loop, daemon=True)
    disp.start()

    admin = threading.Thread(target=admin_cli, daemon=True)
    admin.start()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()

if __name__ == "__main__":
    start_server()