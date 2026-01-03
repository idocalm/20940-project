import sys
import time
import subprocess
import signal
import json
import shutil
from pathlib import Path
from typing import List, Optional
import requests

from attacks.testcase import TestCase
from attacks.bruteforce import BruteforceAttack
from attacks.password_spray import PasswordSprayAttack
from attacks.metrics import AttackMetrics
from attacks.config_manager import ServerConfigManager

# Configuration
BASE_URL = "http://127.0.0.1:5000"
PASSWORDS_DIR = Path("passwords")
TARGET_USERNAME = "testuser"  # For bruteforce
SERVER_PROCESS: Optional[subprocess.Popen] = None


def load_passwords(difficulty: str) -> List[str]:
    """Loads the password list for a given difficulty"""
    file_path = PASSWORDS_DIR / f"{difficulty}_passwords.txt"
    if not file_path.exists():
        raise FileNotFoundError(f"Password file not found: {file_path}")
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def register_test_user(username: str, password: str) -> bool:
    """Registers a test user"""
    try:
        response = requests.post(
            f"{BASE_URL}/register",
            json={"username": username, "password": password, "totp": False},
            timeout=10,
        )
        if response.status_code == 200:
            print(f"User '{username}' created")
            return True
        elif response.status_code == 400:
            print(f"User '{username}' already exists, skipping registration")
            return False
        else:
            print(f"Registration failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"Registration error: {e}")
        return False


def start_server() -> Optional[subprocess.Popen]:
    """Starts the Flask server"""

    print("Starting server...")
    process = subprocess.Popen(
        [sys.executable, "server/server.py"],
    )

    max_retries = 30
    for i in range(max_retries):
        try:
            time.sleep(1)
            response = requests.get(
                f"{BASE_URL}/admin/captcha_token?group_seed=test", timeout=2
            )
            print("Server started successfully")
            return process
        except:
            if i == max_retries - 1:
                print("ERROR: Server failed to start")
                process.terminate()
                return None
            continue

    return process


def stop_server(process: Optional[subprocess.Popen]):
    """Stops the Flask server"""
    if process:
        print("Stopping server...")
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        print("Server stopped")


def setup_signal_handlers(process: Optional[subprocess.Popen]):
    """Setup signal handlers for graceful shutdown"""

    def signal_handler(sig, frame):
        print("\nReceived interrupt signal, shutting down...")
        stop_server(process)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def save_testcase_artifacts(testcase: TestCase, config_mgr: ServerConfigManager):
    """Save logs and config for a testcase to results/{testcase_name}/"""
    results_dir = Path("results") / testcase.name
    results_dir.mkdir(parents=True, exist_ok=True)

    # Save config
    try:
        response = requests.get(f"{BASE_URL}/admin/config", timeout=5)
        if response.status_code == 200:
            config_data = response.json().get("settings", {})
            config_file = results_dir / "config.json"
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2)
            print(f"Saved config to {config_file}")
    except Exception as e:
        print(f"Warning: Could not save config: {e}")

    # Copy requests.log from server folder
    requests_log_src = Path("server/requests.log")
    if requests_log_src.exists():
        requests_log_dst = results_dir / "requests.log"
        try:
            shutil.copy2(requests_log_src, requests_log_dst)
            print(f"Saved requests.log to {requests_log_dst}")
        except Exception as e:
            print(f"Warning: Could not copy requests.log: {e}")

    # Copy attempts.log from root folder
    attempts_log_src = Path("attempts.log")
    if attempts_log_src.exists():
        attempts_log_dst = results_dir / "attempts.log"
        try:
            shutil.copy2(attempts_log_src, attempts_log_dst)
            print(f"Saved attempts.log to {attempts_log_dst}")
        except Exception as e:
            print(f"Warning: Could not copy attempts.log: {e}")


def run_testcase(
    testcase: TestCase, server_process: Optional[subprocess.Popen]
) -> Optional[dict]:
    """
    Runs a single testcase

    Returns:
        Report dictionary if successful, None if fatal error occurred
    """
    print(f"\n{'='*60}")
    print(f"TESTCASE: {testcase.name}")
    print(f"Type: {testcase.testcase_type}")
    print(f"Difficulty: {testcase.difficulty}")
    print(f"Hash Mode: {testcase.hash_mode}")
    print(f"{'='*60}")

    try:
        # Clear logs before starting testcase
        requests_log = Path("server/requests.log")
        attempts_log = Path("attempts.log")
        if requests_log.exists():
            requests_log.write_text("")  # Clear the log file
        if attempts_log.exists():
            attempts_log.write_text("")  # Clear the log file

        # Update server configuration
        config_mgr = ServerConfigManager()
        # Reset to defaults and apply testcase config in one operation
        default_reset = {
            "pepper_enabled": False,
            "captcha_enabled": False,
            "lockout_enabled": False,
            "rate_limit_enabled": False,
            "totp_enabled": False,
        }
        # Merge defaults with testcase config
        merged_config = {**default_reset, **testcase.server_config}
        config_mgr.update_config(config_dict=merged_config)

        print("Server configuration:")
        config_mgr.print_dump()

        # Create metrics
        metrics = AttackMetrics(testcase.name)

        if testcase.testcase_type == "bruteforce":
            passwords = load_passwords(testcase.difficulty)
            
            if testcase.password_index < 0 or testcase.password_index >= len(passwords):
                raise ValueError(f"Invalid password_index: {testcase.password_index}.")
            
            target_password = passwords[testcase.password_index]
            target_username = testcase.name
            print(f"Using password at index {testcase.password_index}: '{target_password}'")
            print(f"Using username: '{target_username}'")

            if not register_test_user(target_username, target_password):
                print(
                    f"Warning: Could not register user '{target_username}', may already exist"
                )

            # Run bruteforce attack
            attacker = BruteforceAttack(BASE_URL)
            found = attacker.attack(
                username=target_username,
                difficulty=testcase.difficulty,
                metrics=metrics,
                delay=testcase.delay,
                max_attempts=testcase.max_attempts,
                max_time=testcase.max_time,
            )

            # Save report
            report = metrics.save_report()
            print(f"\nResults:")
            print(f"   - Attempts: {report['total_attempts']}")
            print(f"   - Time: {report['total_time_seconds']}s")
            print(f"   - Speed: {report['attempts_per_second']} att/s")
            print(f"   - Found: {'Yes' if found else 'No'}")

            # Save testcase artifacts (logs and config)
            save_testcase_artifacts(testcase, config_mgr)

            return report

        elif testcase.testcase_type == "password_spray":
            passwords = load_passwords(testcase.difficulty)

            num_users = min(5, len(passwords))  # TODO: Why 5?
            usernames = []
            for i in range(num_users):
                username = f"user_{testcase.difficulty}_{i}"
                usernames.append(username)
                register_test_user(username, passwords[i])

            # Run password spray attack
            attacker = PasswordSprayAttack(BASE_URL)
            found_credentials = attacker.attack(
                usernames=usernames,
                password_list=passwords,
                metrics=metrics,
                delay=testcase.delay,
                max_time=testcase.max_time,
            )

            # Save report
            report = metrics.save_report()
            report["accounts_compromised"] = len(found_credentials)
            report["total_accounts"] = len(usernames)

            print(f"\nResults:")
            print(f"   - Attempts: {report['total_attempts']}")
            print(f"   - Time: {report['total_time_seconds']}s")
            print(
                f"   - Accounts compromised: {len(found_credentials)}/{len(usernames)}"
            )

            # Save testcase artifacts (logs and config)
            save_testcase_artifacts(testcase, config_mgr)

            return report
        else:
            print(f"ERROR: Unknown testcase type: {testcase.testcase_type}")
            return None

    except KeyboardInterrupt:
        print("\nUser interruption")
        raise
    except Exception as e:
        print(f"ERROR in testcase '{testcase.name}': {e}")
        import traceback

        traceback.print_exc()
        return None


def define_testcases() -> List[TestCase]:
    """Define all testcases to run"""

    MAX_ATTEMPTS = 100000
    MAX_TIME = 4 * 60 * 60

    BF_PASSWORD_INDEXES = [0, 1, 2]

    testcases = []

    for password_index in BF_PASSWORD_INDEXES:
        testcases.append(TestCase(
            name=f"bf_sha256_baseline_{password_index}",
            testcase_type="bruteforce",
            difficulty="easy",
            hash_mode="sha256",
            password_index=password_index,
            server_config={
                "hash_mode": "sha256",
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
            },
            delay=0.01,
            max_attempts=MAX_ATTEMPTS,
            max_time=MAX_TIME,
        )
    )

    return testcases


def main():
    """Runs all testcases sequentially with smart error detection"""
    global SERVER_PROCESS

    print("=" * 60)
    print("STARTING EXPERIMENTS")
    print("=" * 60)

    testcases = define_testcases()
    print(f"\nDefined {len(testcases)} testcases")

    SERVER_PROCESS = start_server()
    setup_signal_handlers(SERVER_PROCESS)

    if SERVER_PROCESS is None:
        pass

    all_reports = []
    
    try:
        for i, testcase in enumerate(testcases, 1):
            print(f"\n[{i}/{len(testcases)}] Running testcase: {testcase.name}")

            report = run_testcase(testcase, SERVER_PROCESS)

            if report is None:
                # Fatal error occurred
                error_msg = f"Fatal error in testcase '{testcase.name}'"
                print(f"ERROR: {error_msg}")

                raise Exception(error_msg)

            all_reports.append(
                {
                    "testcase": testcase.name,
                    "report": report,
                }
            )

        print("\n" + "=" * 60)
        print("ALL TESTCASES COMPLETED")
        print("=" * 60)
        print(f"Successful: {len(all_reports)}/{len(testcases)}")

        print(f"\n{len(all_reports)} reports generated in /results")

    except KeyboardInterrupt:
        print("\nUser interruption")
    finally:
        stop_server(SERVER_PROCESS)


if __name__ == "__main__":
    main()
