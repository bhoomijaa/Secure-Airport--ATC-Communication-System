# show_attack_results.py
import sqlite3
from tabulate import tabulate

DB = "atc_logs.db"

def fetch_attack_rows(limit=200):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # Select rows likely related to attacks / defenses / rejected messages
    cur.execute("""
        SELECT id, timestamp, source_id, event_type, details, status
        FROM logs
        WHERE event_type IN ('ATTACK_SIMULATION','ERROR','ENQUEUED','UNKNOWN','REQUEST','MSG_FROM_PLANE','RUNWAY_ALLOT')
           OR status IN ('REJECTED','TEMP_BANNED','IGNORED','BLOCKED')
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

def print_rows(rows):
    headers = ["id","timestamp","source_id","event_type","details","status"]
    print(tabulate(rows, headers=headers, tablefmt="psql"))

if __name__ == "__main__":
    rows = fetch_attack_rows()
    if not rows:
        print("No attack-related rows found in DB (yet).")
    else:
        print_rows(rows)