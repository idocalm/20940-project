import requests
from typing import Dict, Any, Optional


class ServerConfigManager:
    def __init__(self, base_url: str = "http://127.0.0.1:5000"):
        self.base_url = base_url
        self._current_config: Optional[Dict[str, Any]] = None

    def update_config(self, config_dict: Dict[str, Any] = None, **settings):
        if config_dict:
            settings = {**settings, **config_dict}

        if not settings:
            return

        json_settings = {}
        for key, value in settings.items():
            if isinstance(value, bytes):
                json_settings[key] = value.hex()
            else:
                json_settings[key] = value

        try:
            response = requests.post(
                f"{self.base_url}/admin/config", json=json_settings, timeout=5
            )
            response.raise_for_status()

            result = response.json()
            if "settings" in result:
                self._current_config = result["settings"]
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to update server config: {e}")

    def print_dump(self):
        """Prints current config key/value pairs from the server"""
        try:
            response = requests.get(f"{self.base_url}/admin/config", timeout=5)
            response.raise_for_status()

            config = response.json().get("settings", {})
            self._current_config = config

            print("Current config dump:")
            for key, value in sorted(config.items()):
                if key == "pepper" and isinstance(value, str):
                    try:
                        bytes_val = bytes.fromhex(value)
                        value_str = f'b"{bytes_val.decode()}"' if bytes_val else 'b""'
                    except ValueError:
                        value_str = f'"{value}"'
                elif isinstance(value, str):
                    value_str = f'"{value}"'
                else:
                    value_str = str(value)
                print(f"  {key:<25} = {value_str}")
        except requests.exceptions.RequestException as e:
            print(f"Warning: Could not fetch config from server: {e}")
            if self._current_config:
                print("Using cached config:")
                for key, value in sorted(self._current_config.items()):
                    value_str = f'"{value}"' if isinstance(value, str) else str(value)
                    print(f"  {key:<25} = {value_str}")

    def reset_to_defaults(self):
        self.update_config(
            pepper_enabled=False,
            captcha_enabled=False,
            lockout_enabled=False,
            rate_limit_enabled=False,
            totp_enabled=False,
        )
