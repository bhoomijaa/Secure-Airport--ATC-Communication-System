# attacker.py
import argparse
import socket
import time
import json
import secrets
import os
import security_utils

HOST = '127.0.0.1'
PORT = 65432

def send_one(payload, known_secret=None, show_result=False):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
        signature = security_utils.generate_hmac_signature(payload_bytes, known_secret) if known_secret else "FAKE_SIG"
        payload["signature"] = signature
        encrypted = security_utils.encrypt_message(payload)
        security_utils.send_framed(client, encrypted)

        # try to receive response if any (non-blocking little wait)
        client.settimeout(1.0)
        try:
            data = security_utils.recv_framed(client)
            if data:
                resp = security_utils.decrypt_message(data)
                if show_result:
                    print("[ATTACKER] Received response:", resp)
        except Exception:
            pass
        client.close()
    except Exception as e:
        print("[ATTACKER] send_one error:", e)

def spoof_attack(target_id, fake_sig=None):
    """Single spoofed request with fake signature."""
    payload = {
        "id": target_id,
        "type": "REQUEST_LANDING",
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(8)
    }
    # use explicit fake signature if provided, else default FAKE_SIG
    send_one(payload, known_secret=None, show_result=True)
    print("[ATTACKER] Spoofed packet sent (unsigned/fake).")

def insider_spoof(target_id, secret):
    """Attacker knows the secret and sends properly signed message (insider)."""
    payload = {
        "id": target_id,
        "type": "REQUEST_LANDING",
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(8)
    }
    send_one(payload, known_secret=secret, show_result=True)
    print("[ATTACKER] Insider spoof (signed) packet sent.")

def dos_flood(attacker_id, known_secret=None, count=500, delay=0.005):
    """Flood server to trigger rate limiting / temp ban."""
    print(f"[ATTACKER] Starting DoS: {count} packets (delay {delay}s)")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        for i in range(count):
            payload = {
                "id": attacker_id,
                "type": "SPAM",
                "timestamp": int(time.time()),
                "nonce": secrets.token_hex(8)
            }
            payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
            signature = security_utils.generate_hmac_signature(payload_bytes, known_secret) if known_secret else "FAKE_SIG"
            payload["signature"] = signature
            encrypted = security_utils.encrypt_message(payload)
            try:
                security_utils.send_framed(client, encrypted)
            except Exception:
                # server probably closed connection (due to temp ban)
                break
            if i % 50 == 0:
                print(f"[ATTACKER] sent {i} packets...")
            time.sleep(delay)
        client.close()
    except Exception as e:
        print("[ATTACKER] DoS error:", e)
    print("[ATTACKER] DoS finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["spoof", "insider", "dos"], required=True, help="Attack mode")
    parser.add_argument("--target", default="AIRPLANE_001", help="Target airplane id (for spoof/insider)")
    parser.add_argument("--secret", default=None, help="Known secret (for insider)")
    parser.add_argument("--attacker-id", default="EVIL_BOT_99", help="Attacker id used in DoS/spam")
    parser.add_argument("--count", type=int, default=500, help="Number of packets for DoS")
    parser.add_argument("--delay", type=float, default=0.005, help="Delay between DoS packets")
    args = parser.parse_args()

    if args.mode == "spoof":
        spoof_attack(args.target)
    elif args.mode == "insider":
        if not args.secret:
            print("Insider mode requires --secret (the real airplane secret).")
        else:
            insider_spoof(args.target, args.secret)
    elif args.mode == "dos":
        dos_flood(args.attacker_id, known_secret=args.secret, count=args.count, delay=args.delay)