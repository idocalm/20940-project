from dataclasses import dataclass, field
from typing import Dict, Literal, Optional


@dataclass
class TestCase:
    """Represents a test case for authentication attack experiments"""

    name: str
    testcase_type: Literal["bruteforce", "password_spray"]
    server_config: Dict = field(default_factory=dict)
    difficulty: str = "easy"  # easy, medium, hard, or all
    hash_mode: str = "sha256"  # sha256, bcrypt, argon2id
    max_attempts: Optional[int] = None  # None means try entire solution space
    max_time: Optional[float] = None  # None means no time limit, value in seconds
    delay: float = 0.01  # Delay between attempts in seconds
    password_index: int = 0  # Index of password to use for bruteforce testcases
    run_until_worst: bool = False  # Run to the worst of max_time, max_attempts
    totp_secret: str = None

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
                "rate_limit_enabled": False,
                "rate_limit_window": 60,
                "rate_limit_max": 30,
                "totp_enabled": False,
            }
        else:
            # Ensure hash_mode matches
            if "hash_mode" not in self.server_config:
                self.server_config["hash_mode"] = self.hash_mode
