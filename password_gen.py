from passlib.pwd import genword
from zxcvbn import zxcvbn
from pathlib import Path

COUNT = 10
MAX_ATTEMPTS = 10000

BASE = Path("passwords")
BASE.mkdir(exist_ok=True)

SETS = {
    # name: (entropy, min_score, max_score)
    "easy": (20, 0, 1),
    "medium": (40, 2, 3),
    "hard": (80, 4, 4),
}

"""
The score of each set is between 0-4

0 # too guessable: risky password. (guesses < 10^3)
1 # very guessable: protection from throttled online attacks. (guesses < 10^6)
2 # somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)
3 # safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)
4 # very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)
"""


def score(pw):
    return zxcvbn(pw)["score"]


for name, (entropy, min_s, max_s) in SETS.items():
    out = BASE / f"{name}_passwords.txt"
    passwords = []
    attempts = 0

    while len(passwords) < COUNT:
        if attempts >= MAX_ATTEMPTS:
            raise RuntimeError(f"Cannot satisfy zxcvbn constraints for {name}")

        pw = genword(entropy=entropy)
        s = score(pw)
        attempts += 1

        if min_s <= s <= max_s:
            passwords.append(pw)

    out.write_text("\n".join(passwords) + "\n")

print("Password generation completed")
