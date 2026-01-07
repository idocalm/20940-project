# DOCS

This project consists of three main components:

1. **Authentication Server** (`server/`): A Flask-based web server implementing popular authentication security measures
2. **Attack Tools** (`attacks/`): Automated tools for simulating bruteforce and password spray attacks
3. **Experiment Runner** (`run_experiments.py`): Orchestrates testcases, manages server lifecycle, and collects results

### Features

- Multiple password hashing algorithms (SHA256, bcrypt, Argon2id)
- Security mitigations: Rate limiting, Account lockout, CAPTCHA, TOTP (2FA), Pepper
- Automated attack simulation with metrics collection

## Project Structure

```
project/
├── server/
│   ├── server.py             # Main Flask application and API endpoints
│   ├── storage.py            # Database class for user management
│   ├── utils.py              # Security utilities (hashing, rate limiting, etc.)
│   ├── config.py             # Server configuration settings
│   ├── server.db             # SQLite database (created at runtime)
│   └── requests.log          # HTTP request/response logs
│
├── attacks/
│   ├── testcase.py           # TestCase dataclass definition
│   ├── bruteforce.py         # Bruteforce attack implementation
│   ├── password_spray.py     # Password spray attack implementation
│   ├── password_generator.py # Dynamic password generation for bruteforce
│   ├── config_manager.py     # Server configuration management via API
│   └── metrics.py            # Attack metrics collection and reporting
│
├── passwords/
│   ├── easy_passwords.txt    # Easy difficulty passwords (4 chars)
│   ├── medium_passwords.txt  # Medium difficulty passwords (7 chars)
│   └── hard_passwords.txt    # Hard difficulty passwords (14 chars)
│
├── results/
│   └── {testcase_name}/      # Per-testcase results directory
│       ├── config.json       # Server configuration used
│       ├── requests.log      # HTTP request/response logs
│       └── attempts.log       # Login attempt logs
│
├── run_experiments.py         # Main experiment orchestrator - THIS IS WHAT WE RUN
├── password_gen.py            # Password set generation script - USE THIS TO GENERATE PASSWORDS
├── requirements.txt
└── README.md
```

## Server Implementation

### Architecture

**Endpoints:**

- `POST /register` - User registration
- `POST /login` - User authentication
- `POST /login_totp` - TOTP token verification
- `GET /admin/captcha_token` - CAPTCHA token generation
- `POST /admin/config` - Update server configuration
- `GET /admin/config` - Get current server configuration

#### `storage.py` - Database Layer

```sql
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    hash TEXT NOT NULL,
    salt TEXT,
    totp_secret TEXT
)
```

#### `config.py` - Configuration

```python
SETTINGS = {
    "hash_mode": "sha256",           # sha256 | bcrypt | argon2id
    "bcrypt_cost": 12,               # bcrypt rounds
    "pepper_enabled": False,         # Enable global pepper
    "pepper": b"",                   # Global secret pepper
    "captcha_enabled": False,        # Enable CAPTCHA
    "captcha_after_fails": 5,        # Failures before CAPTCHA
    "lockout_enabled": False,        # Enable account lockout
    "lockout_threshold": 10,         # Failures before lockout
    "rate_limit_enabled": False,     # Enable rate limiting
    "rate_limit_window": 60,         # Rate limit window (seconds)
    "rate_limit_max": 30,            # Max requests per window
    "totp_enabled": False,           # Enable TOTP support
}
```

## Attacks

### TestCase System

**`testcase.py`** - TestCase Dataclass

Defines the structure for experiment testcases:

```python
@dataclass
class TestCase:
    name: str                                    # Unique testcase identifier
    testcase_type: Literal["bruteforce", "password_spray"]
    server_config: Dict                         # Server configuration dict
    difficulty: str = "easy"                     # easy | medium | hard
    hash_mode: str = "sha256"                    # sha256 | bcrypt | argon2id
    max_attempts: Optional[int] = None           # Max attempts (None = unlimited)
    max_time: Optional[float] = None  # None means no time limit, value in seconds
    delay: float = 0.01                          # Delay between attempts (seconds)
```

### Bruteforce Attack

**`bruteforce.py`** - BruteforceAttack Class

- Generates passwords
- Tries passwords systematically against a single target user
- Handles rate limiting, lockout, and CAPTCHA responses

### Password Spray Attack

**`password_spray.py`** - PasswordSprayAttack Class

- Tests each password against multiple users
- Handles account lockouts and rate limiting

### Password Generator ---- attacker side

Please note how this generator is not related to the `password_gen.py` script, which is used by the admin (us)
and not the attacker

**`password_generator.py`** - PasswordGenerator Class

- Generates passwords dynamically for bruteforce attacks
- Tries entire solution space systematically

### Metrics Collection

- Total attempts, successful attempts, failed attempts
- Total time, attempts per second
- Time to breach (first successful login)
- Success rate percentage
- Latency statistics (avg, min, max)
- CPU and memory usage samples

Format example:

```json
{
  "experiment": "testcase_name",
  "timestamp": "2024-01-01T12:00:00",
  "total_attempts": 1000,
  "successful_attempts": 1,
  "failed_attempts": 999,
  "total_time_seconds": 10.5,
  "attempts_per_second": 95.24,
  "time_to_breach_seconds": 8.3,
  "success_rate": 0.1,
  "avg_latency_ms": 10.5,
  "min_latency_ms": 5.0,
  "max_latency_ms": 50.0,
  "avg_cpu_percent": 15.2,
  "avg_memory_mb": 128.5,
  "breached": true
}
```

## Experiment Runner

The runner flow is like this: 

1. **Server starts**
2. **For each testcase:**
   - Clear log files
   - Update server configuration via API
   - Register test users
   - Execute attack (bruteforce or password spray)
   - Collect metrics
   - Save report and artifacts
3. **Server Shutdown**

### Installation

Running password_gen.py also creates the passwords...

```bash
pip install -r requirements.txt
python password_gen.py 
```

### Running Experiments

```bash
python server/server.py
python run_experiments.py
```

### Defining new testcases

Edit `define_testcases()` in `run_experiments.py`:

```python
def define_testcases() -> List[TestCase]:
    testcases = [
        TestCase(
            name="bruteforce_easy_sha256_no_protections",
            testcase_type="bruteforce",
            difficulty="easy",
            hash_mode="sha256",
            server_config={
                "hash_mode": "sha256",
                "rate_limit_enabled": False,
                # ... other settings
            },
            delay=0.01,
            max_attempts=50000,
        ),
        # Add more testcases...
    ]
    return testcases
```

## API Documentation

### POST /register

Register a new user account.

**Request:**

```json
{
  "username": "string",
  "password": "string",
  "totp": false
}
```

**Response:**

- `200 OK`: `{"status": "OK"}`
- `400 Bad Request`: `{"error": "user exists"}`


### POST /login

Authenticate a user.

**Request:**

```json
{
  "username": "string",
  "password": "string"
}
```

**Responses:**

- `200 OK`: `{"success": true}` - Login successful
- `200 OK`: `{"success": false}` - Invalid credentials
- `200 OK`: `{"totp_required": true}` - TOTP code required
- `403 Forbidden`: `{"captcha_required": true}` - CAPTCHA required
- `403 Forbidden`: `{"error": "locked"}` - Account locked
- `429 Too Many Requests`: `{"error": "rate_limited"}` - Rate limited


### POST /login_totp

Verify TOTP token for two-factor authentication.

**Request:**

```json
{
  "username": "string",
  "token": "123456"
}
```

**Response:**

- `200 OK`: `{"success": true}` - Token valid
- `200 OK`: `{"success": false}` - Token invalid
- `400 Bad Request`: `{"error": "invalid"}` - User or TOTP not configured

### GET /admin/captcha_token

Generate CAPTCHA token.

**Param:**

- `group_seed`: Group seed value

**Response:**

- `200 OK`: `{"token": "hex_hmac_string"}`
- `400 Bad Request`: `{"error": "missing group_seed"}`
- `400 Bad Request`: `{"error": "incorrect group_seed"}`

### POST /admin/config

Update server configuration dynamically.

**Request:**

```json
{
  "hash_mode": "bcrypt",
  "rate_limit_enabled": true,
  "rate_limit_max": 30
}
```

**Response:**

- `200 OK`: `{"status": "OK", "settings": {...}}`
- `400 Bad Request`: `{"error": "unknown setting: key"}`

This updates `SETTINGS` dictionary in memory

### GET /admin/config

Get current server configuration.

**Response:**

- `200 OK`: `{"settings": {...}}`

Returns current `SETTINGS` dictionary
