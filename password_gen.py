from pathlib import Path
import random

COUNT = 10

BASE = Path("passwords")
BASE.mkdir(exist_ok=True)

EASY_CHARSET = "abcd0123"  # 8 characters, length 3-4: ~4.6K combinations
MEDIUM_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # Full alphanumeric
HARD_CHARSET = MEDIUM_CHARSET  # Full alphanumeric


def gen_easy_password():
    """Generate easy password: 3-4 chars from restricted charset"""
    length = random.randint(3, 4)
    return "".join(random.choice(EASY_CHARSET) for _ in range(length))


def gen_medium_password():
    """Generate medium password: 5-6 chars from full alphanumeric"""
    length = random.randint(5, 6)
    return "".join(random.choice(MEDIUM_CHARSET) for _ in range(length))


def gen_hard_password():
    """Generate hard password: 8-10 chars from full alphanumeric"""
    length = random.randint(8, 10)
    return "".join(random.choice(HARD_CHARSET) for _ in range(length))


# Generate passwords for each difficulty
for name, gen_func in [("easy", gen_easy_password), ("medium", gen_medium_password), ("hard", gen_hard_password)]:
    out = BASE / f"{name}_passwords.txt"
    passwords = []

    # Generate COUNT unique passwords
    seen = set()
    while len(passwords) < COUNT:
        pw = gen_func()
        if pw not in seen:
            seen.add(pw)
            passwords.append(pw)

    out.write_text("\n".join(passwords) + "\n")

print("Password generation completed")
