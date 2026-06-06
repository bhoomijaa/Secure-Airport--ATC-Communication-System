# check_env.py
import os, json, hashlib
def load_json(p):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception as e:
        return None

print("cwd:", os.getcwd())
print("secrets dir exists:", os.path.isdir("secrets"))
print("airport_secret.json present:", os.path.exists("secrets/airport_secret.json"))
print("airplane_secrets.json present:", os.path.exists("secrets/airplane_secrets.json"))

asf = load_json("secrets/airport_secret.json")
psf = load_json("secrets/airplane_secrets.json")
print("airport_secret loaded:", isinstance(asf, dict) and "airport_secret" in asf)
print("AIRPLANE_001 present:", isinstance(psf, dict) and "AIRPLANE_001" in psf)

if os.path.exists("shared.key"):
    h = hashlib.sha1(open("shared.key","rb").read()).hexdigest()
    print("shared.key sha1:", h)
else:
    print("shared.key: NOT FOUND (it will be created on first run)")