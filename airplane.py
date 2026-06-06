# airplane.py
import socket
import time
import os
import json
import secrets
import threading
import argparse
import security_utils

HOST = '127.0.0.1'
PORT = 65432

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
    return os.environ.get("AIRPORT_SECRET", None)

def load_airplane_secret_from_file(airplane_id):
    try:
        with open(AIRPLANE_SECRETS_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data.get(airplane_id)
    except Exception:
        pass
    return os.environ.get(f"AIRPLANE_SECRET_{airplane_id}") or os.environ.get("AIRPLANE_SECRET")

def listen_for_server(conn, airport_secret, stop_event):
    while not stop_event.is_set():
        data = security_utils.recv_framed(conn)
        if not data:
            stop_event.set()
            break
        msg = security_utils.decrypt_message(data)
        if not msg:
            print("[CLIENT] Failed to decrypt server message.")
            continue

        signature = msg.get("signature")
        if not signature:
            print("[CLIENT] Server message missing signature -> ignoring.")
            continue

        payload = {k: msg[k] for k in msg if k != "signature"}

        # verify server signature
        pb = json.dumps(payload, sort_keys=True).encode('utf-8')
        if not security_utils.verify_hmac_signature(pb, signature, airport_secret):
            print("[CLIENT] Invalid server signature -> ignoring message.")
            continue

        ts = payload.get("timestamp")
        nonce = payload.get("nonce")
        if not security_utils.timestamp_fresh(ts):
            print("[CLIENT] Server message stale -> ignoring.")
            continue
        if security_utils.is_nonce_used("server", nonce):
            print("[CLIENT] Server message nonce reused -> ignoring.")
            continue

        mtype = payload.get("type")
        if mtype == "WEATHER_UPDATE":
            print(f"\n[WEATHER BROADCAST] {payload.get('weather')}\n> ", end='', flush=True)
        elif mtype == "WEATHER_REPLY":
            print(f"\n[WEATHER REPLY] {payload.get('weather')}\n> ", end='', flush=True)
        elif mtype == "RUNWAY_GATE_ALLOTMENT":
            print(f"\n[SERVER ALLOTMENT] {payload.get('msg')} (runway={payload.get('runway')} gate={payload.get('gate')})\n> ", end='', flush=True)
        elif mtype == "ACK" or mtype == "ATC_MESSAGE":
            print(f"\n[SERVER] {payload.get('msg')}\n> ", end='', flush=True)
        else:
            print(f"\n[SERVER MSG] {payload}\n> ", end='', flush=True)

def send_request(conn, airplane_id, airplane_secret, req_type, extra=None, emergency=False):
    nonce = secrets.token_hex(12)
    ts = int(time.time())
    payload = {"id": airplane_id, "type": req_type, "timestamp": ts, "nonce": nonce}
    if extra:
        payload.update(extra)
    if emergency:
        payload['emergency'] = True
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    signature = security_utils.generate_hmac_signature(payload_bytes, airplane_secret)
    payload["signature"] = signature
    encrypted = security_utils.encrypt_message(payload)
    security_utils.send_framed(conn, encrypted)

def menu_loop(conn, airplane_id, airplane_secret, airport_secret, auto_mode=False):
    stop_event = threading.Event()
    listener = threading.Thread(target=listen_for_server, args=(conn, airport_secret, stop_event), daemon=True)
    listener.start()

    def simple_sequence():
        send_request(conn, airplane_id, airplane_secret, "CHECK_WEATHER")
        time.sleep(1)
        send_request(conn, airplane_id, airplane_secret, "REQUEST_LANDING")
        time.sleep(3)
        send_request(conn, airplane_id, airplane_secret, "REQUEST_GATE")
        time.sleep(3)
        send_request(conn, airplane_id, airplane_secret, "REQUEST_TAKEOFF")
        time.sleep(5)
        stop_event.set()
        conn.close()

    if auto_mode:
        simple_sequence()
        return

    prompt = ("\nOptions:\n"
              " 1) Get weather details (one-off)\n"
              " 2) Request landing\n"
              " 3) Request gate\n"
              " 4) Request takeoff\n"
              " 5) Send a message to ATC\n"
              " 6) Declare emergency (low fuel)\n"
              " s) Subscribe to periodic weather broadcasts\n"
              " u) Unsubscribe from periodic weather broadcasts\n"
              " q) Quit\n")
    emergency_declared = False
    print(f"Connected as {airplane_id}. Type an option number.\n{prompt}")
    while True:
        try:
            choice = input("> ").strip()
        except EOFError:
            break
        if choice == "1":
            send_request(conn, airplane_id, airplane_secret, "CHECK_WEATHER")
        elif choice == "2":
            send_request(conn, airplane_id, airplane_secret, "REQUEST_LANDING", emergency=emergency_declared)
        elif choice == "3":
            send_request(conn, airplane_id, airplane_secret, "REQUEST_GATE", emergency=emergency_declared)
        elif choice == "4":
            send_request(conn, airplane_id, airplane_secret, "REQUEST_TAKEOFF", emergency=emergency_declared)
        elif choice == "5":
            msg = input("Message to ATC: ")
            send_request(conn, airplane_id, airplane_secret, "ATC_MESSAGE", extra={"msg": msg})
        elif choice == "6":
            emergency_declared = True
            print("Emergency declared locally; next requests will have emergency flag.")
            send_request(conn, airplane_id, airplane_secret, "EMERGENCY", extra={"reason": "LOW_FUEL"}, emergency=True)
        elif choice == "s":
            send_request(conn, airplane_id, airplane_secret, "SUBSCRIBE_WEATHER")
        elif choice == "u":
            send_request(conn, airplane_id, airplane_secret, "UNSUBSCRIBE_WEATHER")
        elif choice == "q":
            break
        else:
            print("Unknown choice. Choose from menu.")
    stop_event.set()
    conn.close()

def run_airplane(airplane_id="AIRPLANE_001", auto_mode=False):
    secret = load_airplane_secret_from_file(airplane_id)
    airport_secret = load_airport_secret_from_file()
    if secret is None:
        print(f"[{airplane_id}] No airplane secret configured. Put it in secrets/airplane_secrets.json or set env var.")
        return
    if airport_secret is None:
        print(f"[{airplane_id}] No airport secret configured. Put it in secrets/airport_secret.json or set env var.")
        return

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    try:
        menu_loop(client, airplane_id, secret, airport_secret, auto_mode=auto_mode)
    except Exception as e:
        print("Client error:", e)
        client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", default="AIRPLANE_001")
    parser.add_argument("--auto", action="store_true", help="run automatic scripted sequence")
    args = parser.parse_args()
    run_airplane(args.id, auto_mode=args.auto)