import time
import json
import logging
from flask import Flask, request, jsonify

from storage import Database
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
db = Database()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("server/requests.log"),
    ],
)
request_logger = logging.getLogger("requests")


@app.before_request
def log_request():
    """Log incoming request"""
    request_logger.info(
        f"REQUEST: {request.method} {request.path} | "
        f"IP: {request.remote_addr} | "
        f"Headers: {dict(request.headers)}"
    )

    if request.is_json:
        try:
            body = request.get_json(silent=True)
            if body:
                request_logger.info(f"Request Body: {json.dumps(body, indent=2)}")
        except Exception as e:
            request_logger.warning(f"Could not parse request body: {e}")
    elif request.form:
        request_logger.info(f"Request Form: {json.dumps(request.form, indent=2)}")
    elif request.args:
        request_logger.info(f"Request Args: {dict(request.args)}")


@app.after_request
def log_response(response):
    """Log outgoing response"""
    try:
        if response.content_type and "application/json" in response.content_type:
            try:
                response_data_str = response.get_data(as_text=True)
                response.set_data(response_data_str)
                response_data = json.loads(response_data_str)
                request_logger.info(
                    f"RESPONSE: {request.method} {request.path} | "
                    f"Status: {response.status_code} | "
                    f"Body: {json.dumps(response_data, indent=2)}"
                )
            except (json.JSONDecodeError, ValueError):
                request_logger.info(
                    f"RESPONSE: {request.method} {request.path} | "
                    f"Status: {response.status_code} | "
                    f"Content-Type: {response.content_type}"
                )
        else:
            request_logger.info(
                f"RESPONSE: {request.method} {request.path} | "
                f"Status: {response.status_code} | "
                f"Content-Type: {response.content_type or 'N/A'}"
            )
    except Exception as e:
        request_logger.warning(f"Could not log response: {e}")
        request_logger.info(
            f"RESPONSE: {request.method} {request.path} | "
            f"Status: {response.status_code}"
        )

    return response


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]
    totp = data.get("totp", False)

    if db.user_exists(username):
        return jsonify({"error": "user exists"}), 400

    user = hash_password(username, password)

    totp_secret = None
    if SETTINGS["totp_enabled"] and totp:
        totp_secret = pyotp.random_base32()

    db.save_user(
        username=username,
        hash_value=user["hash"],
        salt=user.get("salt"),
        totp_secret=totp_secret,
    )

    return jsonify({"status": "OK"})


@app.route("/login", methods=["POST"])
def login():
    start = time.time()
    data = request.json
    username = data["username"]
    password = data["password"]

    if is_rate_limited(request.remote_addr):  # TODO: by username
        return jsonify({"error": "rate_limited"}), 429

    if locked_out(username):
        return jsonify({"error": "locked"}), 403

    user = db.get_user(username)
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

    user = db.get_user(username)
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


@app.route("/admin/config", methods=["POST"])
def update_config():
    """Update server configuration dynamically"""
    data = request.json
    if not data:
        return jsonify({"error": "missing config data"}), 400

    for key, value in data.items():
        if key in SETTINGS:
            if key == "pepper" and isinstance(value, str):
                try:
                    SETTINGS[key] = bytes.fromhex(value)
                except ValueError:
                    import base64

                    try:
                        SETTINGS[key] = base64.b64decode(value)
                    except Exception:
                        SETTINGS[key] = value.encode() if value else b""
            else:
                SETTINGS[key] = value
        else:
            return jsonify({"error": f"unknown setting: {key}"}), 400

    return jsonify(
        {
            "status": "OK",
            "settings": {
                k: (v.hex() if isinstance(v, bytes) else v) for k, v in SETTINGS.items()
            },
        }
    )


@app.route("/admin/config", methods=["GET"])
def get_config():
    """Get current server configuration"""
    settings_dict = {
        k: (v.hex() if isinstance(v, bytes) else v) for k, v in SETTINGS.items()
    }
    return jsonify({"settings": settings_dict})


if __name__ == "__main__":
    app.run("127.0.0.1", 5000, debug=False)
