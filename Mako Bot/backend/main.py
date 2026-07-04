import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

BOT_TOKEN = os.environ["BOT_TOKEN"]
GUILD_ID  = os.environ["GUILD_ID"]
API_KEY   = os.environ["API_KEY"]

@app.post("/verify")
def verify():
    data = request.get_json(silent=True) or {}
    if data.get("key") != API_KEY:
        return jsonify({"ok": False}), 403
    uid = str(data.get("user_id", "")).strip()
    if not uid.isdigit() or not (17 <= len(uid) <= 19):
        return jsonify({"ok": False}), 400
    try:
        r = requests.get(
            f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{uid}",
            headers={"Authorization": f"Bot {BOT_TOKEN}"},
            timeout=5
        )
        return jsonify({"ok": r.status_code == 200})
    except Exception:
        return jsonify({"ok": False}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
