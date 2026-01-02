from dataclasses import dataclass, field
from typing import Dict, Literal, Optional


@dataclass
class TestCase:
    """Represents a test case for authentication attack experiments"""

    name: str
    testcase_type: Literal["bruteforce", "password_spray"]
    server_config: Dict = field(default_factory=dict)
    difficulty: str = "easy"  # easy, medium, hard
    hash_mode: str = "sha256"  # sha256, bcrypt, argon2id
    max_attempts: Optional[int] = None  # None means try entire solution space
    delay: float = 0.01  # Delay between attempts in seconds

    def __post_init__(self):
        """Set default server config if not provided"""
        if not self.server_config:
            self.server_config = {
                "hash_mode": self.hash_mode,
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
        else:
            # Ensure hash_mode matches
            if "hash_mode" not in self.server_config:
                self.server_config["hash_mode"] = self.hash_mode
