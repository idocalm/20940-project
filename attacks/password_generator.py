import itertools
import string
from typing import Iterator, Optional


class PasswordGenerator:
    """Generates passwords for bruteforce attacks"""

    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    ALPHANUMERIC = LOWERCASE + UPPERCASE + DIGITS  # 62 characters

    EASY_CHARSET = "abcd0123"  # 8 characters

    DIFFICULTY_CONFIG = {
        "easy": {
            "min_length": 4,
            "max_length": 6,
            "charset": EASY_CHARSET,
        },
        "medium": {
            "min_length": 7,
            "max_length": 8,
            "charset": ALPHANUMERIC,
        },
        "hard": {
            "min_length": 8,
            "max_length": 10,
            "charset": ALPHANUMERIC,
        },
    }

    def __init__(self, difficulty: str = "easy", max_attempts: Optional[int] = None):
        """
        Initialize password generator
        difficulty: Password difficulty (easy, medium, hard)
        max_attempts: Maximum number of passwords to generate (None = unlimited)
        """
        if difficulty not in self.DIFFICULTY_CONFIG:
            raise ValueError(f"Unknown difficulty: {difficulty}")

        self.difficulty = difficulty
        self.config = self.DIFFICULTY_CONFIG[difficulty]
        self.max_attempts = max_attempts
        self.attempts = 0

    def generate_bruteforce(self) -> Iterator[str]:
        min_length = self.config["min_length"]
        max_length = self.config["max_length"]
        charset = self.config["charset"]

        for length in range(min_length, max_length + 1):
            for password in itertools.product(charset, repeat=length):
                if self.max_attempts and self.attempts >= self.max_attempts:
                    return
                self.attempts += 1
                yield "".join(password)
