# Server 

## GROUP_SEED: 132130069

The server supports the following endpoints:

1. `/register` - 
2. `/login` - 
3. `/login_totp` -

## SETTINGS
- `hash_mode` 
    = argon2id | bcrypt | sha256
    Password hashing algorithm that is used for all users
- `bcrypt_cost`
    = default at 12 
    bcrypt work factor (rounds), only used if hash_mode == "bcrypt"
- `pepper_enabled`
    Whether a global secret peppr is mixed into password hashing. If false, pepper is never read or used anywhere. 
- `pepper`
    bytes, secret added when pepper_enabled is True. 

## CAPTCHA
- `captcha_enabled` - If true, enables CAPTCHA enforcment after X failures. 
- `captcha_after_fails` - Number of failed login attempts before CAPTCHA is required. Only used if captcha_enabled = True. 

Captcha protects against automated login attempts or brute-force attacks, and reduces risk of password guessing. It's activated after repeated failed login attempts (exactly `SETTINGS["captcha_after_fails"]`)

Server behavior - 
1. CAPTCHA is optional, its controlled by `SETTINGS["captcha_after_fails"]`
2. Once a user exceeds the failure threshold:
    - `/login` responds with `{"captcha_required": true}`
    - The server expects the client to provide a valid CAPTCHA token to proceed
3. CAPTCHA tokens are derived via HMAC using the global pepper and a group seed from `/admin/captcha_token`. 

Flow - 
1. User enters username + password
2. If failed attempts < threshold - normal login
3. If failed attempts >= threshold - receives a CAPTCHA challenge.
4. User solves CAPTCHA (via `/admin/captcha_token`) and sbumits along with credentials
5. If CAPTCHA is correct, login proceeds

## Account Lockout 
- `lockout_enabled` - Enables temporary account lockout after failures. 
- `lockout_threshold` - How many failed login attempts are required to trigger lockout. 
- `lockout_time` - int (seconds), duration of lockout window

## Rate Limiting
- `rate_limit_enabled` - Enables per-IP rate limiting
- `rate_limit_window` - Sliding window size
- `rate_limit_max` - Max requests per window per IP

## TOTP (2FA)
- `totp_enabled` - Globally enable/disable the TOTP support

Purpose - Add a 2FA to accounts, protect against password theft: even if a password is compromised, login requires the TOTP code. 

TOTP is again optional, controlled by `SETTINGS["totp_enabled"]`. The user enables it at registration by passing `totp: true`. The server would then generate a TOTP secret. 

On login:
1. If TOTP is enabled for the user `/login` would respond with `{"totp_required": true}`
2. User then must call `/login_totp` with 6 digit code generated from the secret.

Server uses the standard TOTP algorithm (RFC 6238) which is time-based and changes every 30 seconds. 

## User Storage in `users.json`:
For any user, we store the hash, salt and totp_secret, if such exists (totp is enabled in settings, and user registered with `totp=True`):
```json
{
  "username": {
    "hash": "...",
    "salt": "...",
    "totp_secret": "..."
  }
}
```

## API - server.py

### POST /register
Request json should look like:
```json
{
  "username": "string",
  "password": "string",
  "totp": true
}
```
This endpoint creates a user entry in users.json, Hashes the password using the server settings, and generates and stores a TOTP secret if enabled and also requested.

Errors - 400 exists, username already exists.

### POST /login
```json
{
  "username": "string",
  "password": "string",
}
```

Enforcement order: (if enabled)
1. Rate limit
2. Lockout
3. Password verification
4. TOTP requirement
5. CAPTCHA requirement

Responses:

`{"success": true}`
`{"totp_required": true}`
`{"captcha_required": true}`
`{"error": "rate_limited"}`
`{"error": "locked"}`


### POST /login_totp
```json
{
  "username": "string",
  "token": "123456"
}
```
1. Verifies TOTP token
2. resets failure counter on success 


### GET /admin/captcha_token
- Query parameters - `group_seed`

Response:
```json
{
  "token": "hex_hmac"
}
```
1. Generates CAPTCHA proof token, based on server pepper

## Experiments 
Every experiment needs to log:

1. Total attempts
2. Total time
3. Attempts per second 
4. Time to breach
5. Succcess rate
6. Latency
7. CPU / Memory Usage

# Creating password sets

The python script `password_gen.py` is used to generate the 3 sets of passwords we need - easy medium and hard

We do this with the library `passlib` and `zxcvbn`. The library passlib generates the password based on an entropy field that defines how strong they are. 

The latter can give us an estimation of how strong a password is, from 0 to 4. 

Easy passwords are rated between 0 and 1 
Medium passwords are rated between 2 and 3
Hard are rated as 4
