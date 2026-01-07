import time
import json
import logging
import sys
import os
from flask import Flask, request, jsonify

from storage import Database
import config

config.ATTEMPTS_LOG = os.environ.get("ATTEMPTS_LOG", "attempts.log")

from utils import (
    hash_password,
    verify_password,
    verify_totp,
    log_attempt,
    record_failure,
    is_rate_limited,
    locked_out,
    needs_captcha,
    generate_captcha_token,
    validate_captcha_token,
)
from config import SETTINGS, failed_counts, GROUP_SEED
import pyotp

app = Flask(__name__)
db = Database()

requests_log_path = os.environ.get("REQUESTS_LOG", "server/requests.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(requests_log_path),
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
    totp_secret = data.get("totp_secret", None)

    if db.user_exists(username):
        return jsonify({"error": "user exists"}), 400

    user = hash_password(username, password)

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
    captcha_token_provided = data.get("captcha_token")

    rate_limit_result = is_rate_limited(username)
    if rate_limit_result:
        retry_after = int(rate_limit_result) + 1  # Add 1 second buffer, round up
        response = jsonify({"error": "rate_limited"})
        response.headers["Retry-After"] = str(retry_after)
        return response, 429

    if locked_out(username):
        return jsonify({"error": "locked"}), 403

    if needs_captcha(username):
        request_logger.info("needs captcha")
        if not captcha_token_provided:
            return jsonify({"captcha_required": True}), 403

    if captcha_token_provided and not validate_captcha_token(captcha_token_provided):
        return jsonify({"error": "invalid_captcha"}), 403

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
        },
        username,
    )

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

    if seed == str(GROUP_SEED):
        # Generate a unique CAPTCHA token valid for captcha_after_fails attempts
        token = generate_captcha_token()
        return jsonify({"token": token})

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
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}, using default 5000")
    app.run("127.0.0.1", port, debug=False)
