from collections import defaultdict

SETTINGS = {
    "hash_mode": "sha256",
    "bcrypt_cost": 12,
    "pepper_enabled": False,
    "pepper": b"",
    "captcha_enabled": False,
    "captcha_after_fails": 5,
    "lockout_enabled": False,
    "lockout_threshold": 10,
    "lockout_time": 300,
    "rate_limit_enabled": False,
    "rate_limit_window": 60,
    "rate_limit_max": 30,
    "totp_enabled": False,
}

USERS_FILE = "users.json"
ATTEMPTS_LOG = "attempts.log"
GROUP_SEED = 331771535 ^ 338054042

failed_counts = defaultdict(int)
lockouts = {}
