#!/usr/bin/env python3
import sys
import time
from pathlib import Path

from attacks.bruteforce import BruteforceAttack
from attacks.password_spray import PasswordSprayAttack
from attacks.metrics import AttackMetrics
from attacks.config_manager import ServerConfigManager

# Configuration
BASE_URL = "http://127.0.0.1:5000"
PASSWORDS_DIR = Path("passwords")
TARGET_USERNAME = "testuser"  # Pour bruteforce

def load_passwords(difficulty):
    """Loads the password list for a given difficulty"""
    file_path = PASSWORDS_DIR / f"{difficulty}_passwords.txt"
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def register_test_user(username, password):
    """Registers a test user"""
    import requests
    try:
        response = requests.post(
            f"{BASE_URL}/register",
            json={"username": username, "password": password, "totp": False}
        )
        if response.status_code == 200:
            print(f"✅ User '{username}' created")
            return True
        else:
            print(f"⚠️  User already exists or error")
            return False
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return False

def run_bruteforce_experiment(difficulty, hash_mode):
    """Runs a bruteforce experiment"""
    experiment_name = f"bruteforce_{difficulty}_{hash_mode}"
    print(f"\n{'='*60}")
    print(f"🧪 EXPERIMENT: {experiment_name}")
    print(f"{'='*60}")
    
    # Configuration
    config_mgr = ServerConfigManager()
    config_mgr.reset_to_defaults()
    config_mgr.update_config(hash_mode=hash_mode)
    
    print("⏳ Waiting 2 seconds for server restart...")
    time.sleep(2)
    
    # Load passwords
    passwords = load_passwords(difficulty)
    target_password = passwords[0]  # Take the first one
    
    # Create test user
    register_test_user(TARGET_USERNAME, target_password)
    
    # Launch attack
    metrics = AttackMetrics(experiment_name)
    attacker = BruteforceAttack(BASE_URL)
    
    found = attacker.attack(TARGET_USERNAME, passwords, metrics, delay=0.01)
    
    # Save report
    report = metrics.save_report()
    print(f"\n📈 Results:")
    print(f"   - Attempts: {report['total_attempts']}")
    print(f"   - Time: {report['total_time_seconds']}s")
    print(f"   - Speed: {report['attempts_per_second']} att/s")
    print(f"   - Found: {'Yes' if found else 'No'}")
    
    return report

def run_password_spray_experiment(difficulty, hash_mode):
    """Runs a password spray experiment"""
    experiment_name = f"spray_{difficulty}_{hash_mode}"
    print(f"\n{'='*60}")
    print(f"🧪 EXPERIMENT: {experiment_name}")
    print(f"{'='*60}")
    
    # Configuration
    config_mgr = ServerConfigManager()
    config_mgr.reset_to_defaults()
    config_mgr.update_config(hash_mode=hash_mode)
    
    print("⏳ Waiting 2 seconds for server restart...")
    time.sleep(2)
    
    # Load passwords
    passwords = load_passwords(difficulty)
    
    # Create 5 test users with different passwords
    usernames = []
    for i in range(min(5, len(passwords))):
        username = f"user_{difficulty}_{i}"
        usernames.append(username)
        register_test_user(username, passwords[i])
    
    # Launch attack
    metrics = AttackMetrics(experiment_name)
    attacker = PasswordSprayAttack(BASE_URL)
    
    found = attacker.attack(usernames, passwords, metrics, delay=0.1)
    
    # Save report
    report = metrics.save_report()
    print(f"\n📈 Results:")
    print(f"   - Attempts: {report['total_attempts']}")
    print(f"   - Time: {report['total_time_seconds']}s")
    print(f"   - Accounts compromised: {len(found)}/{len(usernames)}")
    
    return report

def main():
    """Runs all experiments"""
    difficulties = ["easy", "medium", "hard"]
    hash_modes = ["sha256", "bcrypt", "argon2id"]
    
    print("🚀 STARTING EXPERIMENTS")
    print("="*60)
    
    all_reports = []
    
    # Phase 1: Bruteforce without protections
    print("\n📍 PHASE 1: BRUTEFORCE ATTACKS")
    for difficulty in difficulties:
        for hash_mode in hash_modes:
            try:
                report = run_bruteforce_experiment(difficulty, hash_mode)
                all_reports.append(report)
            except KeyboardInterrupt:
                print("\n⚠️  User interruption")
                sys.exit(0)
            except Exception as e:
                print(f"❌ Error: {e}")
    
    # Phase 2: Password Spray without protections
    print("\n📍 PHASE 2: PASSWORD SPRAY ATTACKS")
    for difficulty in difficulties:
        for hash_mode in hash_modes:
            try:
                report = run_password_spray_experiment(difficulty, hash_mode)
                all_reports.append(report)
            except KeyboardInterrupt:
                print("\n⚠️  User interruption")
                sys.exit(0)
            except Exception as e:
                print(f"❌ Error: {e}")
    
    print("\n" + "="*60)
    print("✅ ALL EXPERIMENTS COMPLETED")
    print(f"📊 {len(all_reports)} reports generated in /results")

if __name__ == "__main__":
    main()

