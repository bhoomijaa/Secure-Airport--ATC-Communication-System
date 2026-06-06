python3 atc_server.py

python3 airplane.py --id AIRPLANE_001


attacker:
python3 attacker.py --mode spoof --target AIRPLANE_001

python3 attacker.py --mode dos --attacker-id EVIL_BOT_99 --count 800 --delay 0.003

python3 attacker.py --mode insider --target AIRPLANE_001 --secret secret-plane-001-xyz


database:

sqlite3 atc_logs.db "SELECT id,timestamp,source_id,event_type,details,status FROM logs ORDER BY id DESC LIMIT 50;"

sqlite3 atc_logs.db "SELECT id,timestamp,source_id,event_type,details,status FROM logs WHERE event_type='ATTACK_SIMULATION' OR status IN ('REJECTED','TEMP_BANNED','IGNORED') ORDER BY id DESC LIMIT 50;"

python3 show_attack_results.py


DB check for emergency events:
sqlite3 atc_logs.db "SELECT id,timestamp,source_id,event_type,details,status FROM logs WHERE event_type='ENQUEUED' OR event_type='ALLOTMENT' ORDER BY id DESC LIMIT 100;"