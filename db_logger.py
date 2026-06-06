# db_logger.py
import sqlite3
from datetime import datetime
import threading
import os

DB_NAME = "atc_logs.db"
_lock = threading.Lock()

def init_db():
    with _lock:
        created = not os.path.exists(DB_NAME)
        conn = sqlite3.connect(DB_NAME, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_id TEXT,
                event_type TEXT,
                details TEXT,
                status TEXT
            )
        ''')
        conn.commit()
        conn.close()
        if created:
            print(f"[DB] Database '{DB_NAME}' initialized (WAL mode).")

def log_event(source_id, event_type, details, status):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with _lock:
            conn = sqlite3.connect(DB_NAME, timeout=30, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO logs (timestamp, source_id, event_type, details, status) VALUES (?, ?, ?, ?, ?)",
                           (timestamp, source_id, event_type, details, status))
            conn.commit()
            conn.close()
        print(f"[LOG] {source_id} | {event_type}: {status} | {details}")
    except Exception as e:
        print(f"[DB ERROR] Failed to log event: {e}")