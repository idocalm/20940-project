import time
import json
import hashlib
import hmac
from collections import defaultdict, deque

from passlib.hash import bcrypt, argon2
import pyotp

from config import SETTINGS, ATTEMPTS_LOG, failed_counts, lockouts

rate_limited = defaultdict(deque)


def log_attempt(entry):
    def normalize(obj):
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, dict):
            return {k: normalize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [normalize(v) for v in obj]
        return obj

    entry = normalize(entry)

    with open(ATTEMPTS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _pepper():
    return SETTINGS["pepper"] if SETTINGS["pepper_enabled"] else b""


def hash_password(username, password):
    mode = SETTINGS["hash_mode"]
    pepper = _pepper()

    if mode == "sha256":
        salt = hashlib.sha256(username.encode()).digest()
        h = hashlib.sha256(salt + password.encode() + pepper).hexdigest()
        return {"hash": h, "salt": salt.hex()}

    if mode == "bcrypt":
        bcrypt.using(rounds=SETTINGS["bcrypt_cost"])
        return {"hash": bcrypt.hash(password + pepper.decode())}

    if mode == "argon2id":
        return {"hash": argon2.hash(password + pepper.decode())}

    raise ValueError("Invalid hash mode")


def verify_password(user, password):
    mode = SETTINGS["hash_mode"]
    pepper = _pepper()

    if mode == "sha256":
        salt = bytes.fromhex(user["salt"])
        h = hashlib.sha256(salt + password.encode() + pepper).hexdigest()
        return h == user["hash"]

    if mode == "bcrypt":
        return bcrypt.verify(password + pepper.decode(), user["hash"])

    if mode == "argon2id":
        return argon2.verify(password + pepper.decode(), user["hash"])

    return False


def is_rate_limited(key):
    if not SETTINGS["rate_limit_enabled"]:
        return False

    now = time.time()
    q = rate_limited[key]
    while q and q[0] < now - SETTINGS["rate_limit_window"]:
        q.popleft()

    if len(q) >= SETTINGS["rate_limit_max"]:
        return True

    q.append(now)
    return False


def record_failure(username):
    failed_counts[username] += 1

    if (
        SETTINGS["lockout_enabled"]
        and failed_counts[username] >= SETTINGS["lockout_threshold"]
    ):
        lockouts[username] = time.time() + SETTINGS["lockout_time"]


def locked_out(username):
    if not SETTINGS["lockout_enabled"]:
        return False
    until = lockouts.get(username)
    return until is not None and time.time() < until


def needs_captcha(username):
    return (
        SETTINGS["captcha_enabled"]
        and failed_counts[username] >= SETTINGS["captcha_after_fails"]
    )


def verify_totp(user, token):
    if not SETTINGS["totp_enabled"]:
        return True
    totp = pyotp.TOTP(user["totp_secret"])
    return totp.verify(token, valid_window=1)


def captcha_token(group_seed):
    return hmac.new(
        SETTINGS["pepper"], msg=group_seed.encode(), digestmod=hashlib.sha256
    ).hexdigest()
