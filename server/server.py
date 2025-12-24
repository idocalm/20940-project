import time
from flask import Flask, request, jsonify

from storage import load_users, save_users
from utils import (
    hash_password,
    verify_password,
    verify_totp,
    log_attempt,
    record_failure,
    is_rate_limited,
    locked_out,
    needs_captcha,
    captcha_token,
)
from config import SETTINGS, failed_counts, GROUP_SEED
import pyotp

app = Flask(__name__)
users = load_users()


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]
    totp = data.get("totp", False)

    if username in users:
        return jsonify({"error": "user exists"}), 400

    user = hash_password(username, password)

    if SETTINGS["totp_enabled"] and totp:
        user["totp_secret"] = pyotp.random_base32()

    users[username] = user
    save_users(users)

    return jsonify({"status": "OK"})


@app.route("/login", methods=["POST"])
def login():
    start = time.time()
    data = request.json
    username = data["username"]
    password = data["password"]

    if is_rate_limited(request.remote_addr):
        return jsonify({"error": "rate_limited"}), 429

    if locked_out(username):
        return jsonify({"error": "locked"}), 403

    user = users.get(username)
    success = False
    reason = "fail"

    if user and verify_password(user, password):
        if SETTINGS["totp_enabled"] and "totp_secret" in user:
            reason = "totp_required"
        else:
            success = True
            failed_counts[username] = 0
            reason = "success"
    else:
        record_failure(username)

    log_attempt(
        {
            "ts": time.time(),
            "username": username,
            "result": reason,
            "latency_ms": int((time.time() - start) * 1000),
            "settings": SETTINGS,
        }
    )

    if needs_captcha(username):
        return jsonify({"captcha_required": True}), 403

    if reason == "totp_required":
        return jsonify({"totp_required": True}), 401

    return jsonify({"success": success})


@app.route("/login_totp", methods=["POST"])
def login_totp():
    data = request.json
    username = data["username"]
    token = data["token"]

    user = users.get(username)
    if not user or "totp_secret" not in user:
        return jsonify({"error": "invalid"}), 400

    if verify_totp(user, token):
        failed_counts[username] = 0
        return jsonify({"success": True})

    record_failure(username)
    return jsonify({"success": False}), 401


@app.route("/admin/captcha_token", methods=["GET"])
def get_captcha():
    seed = request.args.get("group_seed")
    if not seed:
        return jsonify({"error": "missing group_seed"}), 400

    if seed == GROUP_SEED:
        return jsonify({"token": captcha_token(seed)})

    return jsonify({"error": "incorrect group_seed"}), 400


if __name__ == "__main__":
    app.run("127.0.0.1", 5000, debug=False)
