import os
import json
import urllib.parse
from datetime import datetime, timezone

import requests
from flask import Flask, redirect, request, url_for, render_template_string

app = Flask(__name__)

# ---------------- CONFIG ----------------
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
RC_LOGS_WEBHOOK = os.getenv("RC_LOGS_WEBHOOK")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")  # For guild checks

OAUTH_SCOPE = "identify email guilds guilds.members.read"  # Enhanced scopes
DISCORD_API_BASE = "https://discord.com/api"
SITE_NAME = "Enchanted Verification"

# VPN/Proxy detection threshold (0-100, higher = stricter)
VPN_BLOCK_THRESHOLD = 75
BLOCK_VPNS = True  # Set to False to only detect but not block

# Advanced security settings
ENABLE_FINGERPRINTING = True
ENABLE_DUPLICATE_DETECTION = True
ENABLE_MUTUAL_SERVERS = True
MIN_ACCOUNT_AGE_DAYS = 0  # Set to 7, 14, 30 to block young accounts
MAX_ALT_RISK_SCORE = 100  # Block accounts above this score (100 = no blocking)

# Database for tracking (simple JSON file)
DATABASE_FILE = "verifications.json"

# ---------------- HTML TEMPLATES ----------------

VERIFY_PAGE_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{{ site_name }}</title>
    <style>
      body {
        background-color: #0b0214;
        color: #ffffff;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        margin: 0;
      }
      .card {
        background-color: #1c0333;
        padding: 32px;
        border-radius: 16px;
        text-align: center;
        max-width: 420px;
        width: 100%;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      }
      h1 {
        margin-bottom: 8px;
      }
      p {
        margin-bottom: 24px;
        color: #d0c6e8;
      }
      a.button {
        display: inline-block;
        padding: 12px 24px;
        border-radius: 999px;
        text-decoration: none;
        background: #5865F2;
        color: white;
        font-weight: 600;
      }
      a.button:hover {
        opacity: 0.9;
      }
      .privacy {
        font-size: 12px;
        color: #888;
        margin-top: 16px;
      }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>{{ site_name }}</h1>
      <p>Click the button below to verify your Discord account.</p>
      <a class="button" href="{{ oauth_url }}">Click to verify</a>
      <p class="privacy">By verifying, you agree to connect your Discord account. We collect your username, email, ID, IP address, and browser information for security purposes.</p>
    </div>
  </body>
</html>
"""

SUCCESS_PAGE_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{{ site_name }} - Verified</title>
    <style>
      body {
        background-color: #0b0214;
        color: #ffffff;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        margin: 0;
      }
      .card {
        background-color: #1c0333;
        padding: 32px;
        border-radius: 16px;
        text-align: center;
        max-width: 420px;
        width: 100%;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      }
      h1 {
        margin-bottom: 8px;
      }
      p {
        margin-bottom: 16px;
        color: #d0c6e8;
      }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Verification complete ✅</h1>
      <p>You can now return to the Discord server.</p>
      <p><small>Account: {{ username }} (ID: {{ user_id }})</small></p>
    </div>
  </body>
</html>
"""

ERROR_PAGE_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{{ site_name }} - Error</title>
    <style>
      body {
        background-color: #0b0214;
        color: #ffffff;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        margin: 0;
      }
      .card {
        background-color: #330308;
        padding: 32px;
        border-radius: 16px;
        text-align: center;
        max-width: 420px;
        width: 100%;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Verification failed ❌</h1>
      <p>{{ message }}</p>
    </div>
  </body>
</html>
"""

# ---------------- HELPER FUNCTIONS ----------------

def load_database():
    """Load verification database"""
    if os.path.exists(DATABASE_FILE):
        try:
            with open(DATABASE_FILE, 'r') as f:
                return json.load(f)
        except:
            return {"verifications": [], "ip_history": {}, "fingerprints": {}}
    return {"verifications": [], "ip_history": {}, "fingerprints": {}}


def save_database(db):
    """Save verification database"""
    try:
        with open(DATABASE_FILE, 'w') as f:
            json.dump(db, f, indent=2)
    except Exception as e:
        print(f"Failed to save database: {e}")


def generate_browser_fingerprint(request_obj):
    """Generate a unique browser fingerprint"""
    import hashlib
    
    # Collect browser characteristics
    user_agent = request_obj.headers.get('User-Agent', '')
    accept = request_obj.headers.get('Accept', '')
    accept_language = request_obj.headers.get('Accept-Language', '')
    accept_encoding = request_obj.headers.get('Accept-Encoding', '')
    
    # Create fingerprint hash
    fingerprint_string = f"{user_agent}|{accept}|{accept_language}|{accept_encoding}"
    fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
    
    return {
        'fingerprint': fingerprint,
        'user_agent': user_agent,
        'accept_language': accept_language,
        'accept_encoding': accept_encoding
    }


def check_duplicate_verification(user_id, ip_address, fingerprint):
    """Check if this user/IP/fingerprint has verified before"""
    db = load_database()
    
    result = {
        'is_duplicate': False,
        'previous_verifications': 0,
        'same_ip_count': 0,
        'same_fingerprint_count': 0,
        'last_verification': None,
        'suspicious_pattern': False
    }
    
    # Check previous verifications for this user
    user_verifications = [v for v in db['verifications'] if v.get('user_id') == user_id]
    result['previous_verifications'] = len(user_verifications)
    result['is_duplicate'] = len(user_verifications) > 0
    
    if user_verifications:
        result['last_verification'] = user_verifications[-1].get('timestamp')
    
    # Check IP history
    if ip_address in db['ip_history']:
        result['same_ip_count'] = len(db['ip_history'][ip_address])
        
        # If multiple different users from same IP in short time = suspicious
        if len(db['ip_history'][ip_address]) > 3:
            result['suspicious_pattern'] = True
    
    # Check fingerprint history
    if fingerprint in db['fingerprints']:
        result['same_fingerprint_count'] = len(db['fingerprints'][fingerprint])
        
        # Multiple accounts from same browser = suspicious
        if len(db['fingerprints'][fingerprint]) > 2:
            result['suspicious_pattern'] = True
    
    return result


def save_verification(user_id, ip_address, fingerprint, email):
    """Save verification to database for tracking"""
    db = load_database()
    
    verification = {
        'user_id': user_id,
        'ip_address': ip_address,
        'fingerprint': fingerprint,
        'email': email,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    db['verifications'].append(verification)
    
    # Track IP history
    if ip_address not in db['ip_history']:
        db['ip_history'][ip_address] = []
    db['ip_history'][ip_address].append(user_id)
    
    # Track fingerprint history
    if fingerprint not in db['fingerprints']:
        db['fingerprints'][fingerprint] = []
    db['fingerprints'][fingerprint].append(user_id)
    
    # Keep only last 1000 verifications to prevent file bloat
    if len(db['verifications']) > 1000:
        db['verifications'] = db['verifications'][-1000:]
    
    save_database(db)


def get_user_guilds(access_token):
    """Get list of servers the user is in"""
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        r = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=headers, timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"Failed to get user guilds: {e}")
    
    return []


def check_mutual_servers(guilds):
    """Check which servers are mutual with your bot"""
    if not DISCORD_BOT_TOKEN or not ENABLE_MUTUAL_SERVERS:
        return {
            'mutual_count': 0,
            'mutual_servers': [],
            'total_servers': len(guilds)
        }
    
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    
    try:
        # Get bot's guilds
        r = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=headers, timeout=5)
        if r.status_code != 200:
            return {'mutual_count': 0, 'mutual_servers': [], 'total_servers': len(guilds)}
        
        bot_guilds = {g['id'] for g in r.json()}
        user_guild_ids = {g['id'] for g in guilds}
        
        mutual = user_guild_ids.intersection(bot_guilds)
        mutual_servers = [g for g in guilds if g['id'] in mutual]
        
        return {
            'mutual_count': len(mutual),
            'mutual_servers': [{'name': g['name'], 'id': g['id']} for g in mutual_servers[:5]],  # First 5
            'total_servers': len(guilds)
        }
    except Exception as e:
        print(f"Failed to check mutual servers: {e}")
        return {'mutual_count': 0, 'mutual_servers': [], 'total_servers': len(guilds)}


def check_phone_verification(user):
    """Check if user has phone verification"""
    return user.get('phone') is not None or user.get('verified', False)


def get_account_flags(user):
    """Decode Discord account flags"""
    flags_value = user.get('public_flags', 0) or user.get('flags', 0)
    
    flag_names = {
        1 << 0: "Discord Employee",
        1 << 1: "Partnered Server Owner",
        1 << 2: "HypeSquad Events",
        1 << 3: "Bug Hunter Level 1",
        1 << 6: "HypeSquad Bravery",
        1 << 7: "HypeSquad Brilliance",
        1 << 8: "HypeSquad Balance",
        1 << 9: "Early Supporter",
        1 << 10: "Team User",
        1 << 14: "Bug Hunter Level 2",
        1 << 16: "Verified Bot",
        1 << 17: "Early Verified Bot Developer",
        1 << 18: "Discord Certified Moderator",
        1 << 19: "Bot HTTP Interactions",
        1 << 22: "Active Developer"
    }
    
    badges = []
    for flag, name in flag_names.items():
        if flags_value & flag:
            badges.append(name)
    
    return badges


def get_client_ip():
    """Get the user's IP address, accounting for proxies"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip


def check_vpn_proxy(ip_address):
    """
    Check if IP is VPN/Proxy using multiple free services
    Returns dict with detection info
    """
    result = {
        'is_vpn': False,
        'is_proxy': False,
        'is_tor': False,
        'risk_score': 0,
        'service': 'None',
        'blocked': False
    }
    
    try:
        # Using IPHub (free tier: 1000 requests/day, no key for first 1000)
        # Register at iphub.info for API key if needed
        response = requests.get(f"http://v2.api.iphub.info/ip/{ip_address}", 
                              headers={'X-Key': os.getenv('IPHUB_API_KEY', 'free')},
                              timeout=3)
        
        if response.status_code == 200:
            data = response.json()
            block_type = data.get('block', 0)
            
            # block: 0 = Residential/Business, 1 = VPN/Proxy, 2 = Tor
            if block_type == 1:
                result['is_vpn'] = True
                result['is_proxy'] = True
                result['risk_score'] = 90
                result['service'] = 'IPHub'
            elif block_type == 2:
                result['is_tor'] = True
                result['risk_score'] = 100
                result['service'] = 'IPHub'
    except Exception as e:
        print(f"IPHub check failed: {e}")
    
    # Fallback to ip-api.com proxy detection
    if result['risk_score'] == 0:
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=proxy,hosting", timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get('proxy') or data.get('hosting'):
                    result['is_proxy'] = True
                    result['risk_score'] = 70
                    result['service'] = 'ip-api'
        except Exception as e:
            print(f"ip-api proxy check failed: {e}")
    
    # Determine if should block
    if BLOCK_VPNS and result['risk_score'] >= VPN_BLOCK_THRESHOLD:
        result['blocked'] = True
    
    return result


def get_ip_location(ip_address):
    """Get location information from IP address"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'isp': data.get('isp', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown')
                }
    except Exception as e:
        print(f"Failed to get IP location: {e}")
    
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'region': 'Unknown',
        'latitude': None,
        'longitude': None,
        'isp': 'Unknown',
        'timezone': 'Unknown'
    }


def calculate_account_age(user_id):
    """Calculate Discord account age from snowflake ID"""
    try:
        discord_epoch = 1420070400000
        timestamp = ((int(user_id) >> 22) + discord_epoch) / 1000
        created_at = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        age = datetime.now(timezone.utc) - created_at
        
        days = age.days
        years = days // 365
        months = (days % 365) // 30
        remaining_days = (days % 365) % 30
        
        age_parts = []
        if years > 0:
            age_parts.append(f"{years}y")
        if months > 0:
            age_parts.append(f"{months}mo")
        if remaining_days > 0 or not age_parts:
            age_parts.append(f"{remaining_days}d")
        
        return {
            'created_at': created_at.isoformat(),
            'age_days': days,
            'age_formatted': ' '.join(age_parts),
            'is_new': days < 30,  # Account less than 30 days old
            'is_suspicious': days < 7  # Account less than 7 days old
        }
    except Exception as e:
        print(f"Failed to calculate account age: {e}")
        return {
            'created_at': 'Unknown',
            'age_days': 0,
            'age_formatted': 'Unknown',
            'is_new': False,
            'is_suspicious': False
        }


def detect_alt_account(user, account_age, ip_info, duplicate_check, guilds_info, badges):
    """
    Enhanced alt detection with more factors
    """
    risk_score = 0
    flags = []
    
    # Check account age
    if account_age['is_suspicious']:
        risk_score += 40
        flags.append("Account less than 7 days old")
    elif account_age['is_new']:
        risk_score += 20
        flags.append("Account less than 30 days old")
    
    # Check if avatar is default
    if not user.get('avatar'):
        risk_score += 15
        flags.append("No custom avatar")
    
    # Check if no banner
    if not user.get('banner'):
        risk_score += 5
        flags.append("No custom banner")
    
    # Check username patterns
    username = user.get('username', '')
    if any(char.isdigit() for char in username[-4:]):
        risk_score += 10
        flags.append("Numeric username pattern")
    
    # Check if email is verified
    if not user.get('verified', False):
        risk_score += 25
        flags.append("Email not verified")
    
    # Check for VPN/Proxy usage on new accounts
    if ip_info.get('vpn_detected', False) and account_age['is_new']:
        risk_score += 30
        flags.append("VPN usage on new account")
    
    # NEW: Check duplicate verifications
    if duplicate_check['previous_verifications'] > 0:
        risk_score += 15
        flags.append(f"Already verified {duplicate_check['previous_verifications']} time(s)")
    
    # NEW: Check suspicious patterns (multiple accounts from same IP/browser)
    if duplicate_check['suspicious_pattern']:
        risk_score += 35
        flags.append("Suspicious pattern detected (multiple accounts)")
    
    # NEW: Very few servers = suspicious for new accounts
    if guilds_info['total_servers'] < 3 and account_age['is_new']:
        risk_score += 15
        flags.append("Very few servers for new account")
    
    # NEW: No mutual servers with bot
    if guilds_info['mutual_count'] == 0 and guilds_info['total_servers'] > 0:
        risk_score += 10
        flags.append("No mutual servers")
    
    # Positive factors (reduce risk)
    if user.get('premium_type'):
        risk_score = max(0, risk_score - 20)
        flags.append("✓ Has Nitro")
    
    # NEW: Has badges = more legitimate
    if len(badges) > 0:
        risk_score = max(0, risk_score - 15)
        flags.append(f"✓ Has {len(badges)} badge(s)")
    
    # NEW: In many mutual servers = legitimate
    if guilds_info['mutual_count'] >= 3:
        risk_score = max(0, risk_score - 15)
        flags.append(f"✓ {guilds_info['mutual_count']} mutual servers")
    
    # Cap risk score
    risk_score = min(risk_score, 100)
    
    return {
        'risk_score': risk_score,
        'flags': flags,
        'is_likely_alt': risk_score >= 60,
        'risk_level': 'High' if risk_score >= 70 else 'Medium' if risk_score >= 40 else 'Low'
    }


def build_oauth_url():
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": OAUTH_SCOPE,
        "prompt": "consent"
    }
    return f"{DISCORD_API_BASE}/oauth2/authorize?{urllib.parse.urlencode(params)}"


def exchange_code(code: str) -> dict | None:
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    r = requests.post(f"{DISCORD_API_BASE}/oauth2/token", data=data, headers=headers)
    if r.status_code != 200:
        print("Token exchange failed:", r.text)
        return None
    return r.json()


def get_discord_user(access_token: str) -> dict | None:
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    r = requests.get(f"{DISCORD_API_BASE}/users/@me", headers=headers)
    if r.status_code != 200:
        print("Get user failed:", r.text)
        return None
    return r.json()


def send_verification_log(user: dict, ip_info: dict, account_age: dict, alt_detection: dict, 
                         vpn_check: dict, duplicate_check: dict, guilds_info: dict, 
                         fingerprint_info: dict, badges: list):
    """
    Sends an enhanced embed with ALL collected data
    """
    if not RC_LOGS_WEBHOOK:
        print("No RC_LOGS_WEBHOOK configured")
        return

    username = user.get('username', 'Unknown')
    discriminator = user.get('discriminator', '0')
    if discriminator != '0':
        username = f"{username}#{discriminator}"
    
    user_id = user.get("id", "Unknown")
    avatar_hash = user.get("avatar")
    email = user.get("email", "Not provided")
    email_verified = "✅ Verified" if user.get("verified", False) else "❌ Not verified"
    
    # Nitro status
    premium_type = user.get("premium_type")
    nitro_status = {
        0: "None",
        1: "Nitro Classic",
        2: "Nitro",
        3: "Nitro Basic"
    }.get(premium_type, "None")
    
    # Banner and avatar
    has_banner = "✅ Yes" if user.get("banner") else "❌ No"
    has_avatar = "✅ Yes" if avatar_hash else "❌ No (Default)"
    
    # Badges
    badges_text = ", ".join(badges[:3]) if badges else "None"
    if len(badges) > 3:
        badges_text += f" +{len(badges)-3} more"

    avatar_url = None
    if avatar_hash and user_id:
        avatar_url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png?size=256"

    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    user_agent_short = ip_info['user_agent'][:150] if ip_info['user_agent'] else 'Unknown'

    # Color based on risk level
    embed_color = 0x6f3bbd  # Default purple
    if vpn_check['blocked']:
        embed_color = 0xff0000  # Red for blocked
    elif alt_detection['is_likely_alt']:
        embed_color = 0xff8800  # Orange for high risk
    elif alt_detection['risk_score'] >= 40:
        embed_color = 0xffcc00  # Yellow for medium risk

    # VPN/Proxy status
    vpn_status = "❌ Clean"
    if vpn_check['is_tor']:
        vpn_status = "🔴 TOR Detected"
    elif vpn_check['is_vpn']:
        vpn_status = "🟡 VPN/Proxy Detected"
    
    if vpn_check['blocked']:
        vpn_status += " (BLOCKED)"

    # Alt detection summary
    alt_status = f"{alt_detection['risk_level']} Risk ({alt_detection['risk_score']}%)"
    if alt_detection['is_likely_alt']:
        alt_status = "⚠️ " + alt_status

    # Duplicate status
    duplicate_status = "✅ First time"
    if duplicate_check['previous_verifications'] > 0:
        duplicate_status = f"⚠️ {duplicate_check['previous_verifications']} previous verification(s)"
    
    # Mutual servers
    mutual_text = f"{guilds_info['mutual_count']}/{guilds_info['total_servers']} servers"
    if guilds_info['mutual_servers']:
        mutual_names = [s['name'][:20] for s in guilds_info['mutual_servers'][:2]]
        mutual_text += f"\n{', '.join(mutual_names)}"
        if len(guilds_info['mutual_servers']) > 2:
            mutual_text += f" +{len(guilds_info['mutual_servers'])-2} more"

    # Suspicious patterns
    pattern_text = "None detected"
    if duplicate_check['suspicious_pattern']:
        pattern_text = f"⚠️ {duplicate_check['same_ip_count']} users from IP\n{duplicate_check['same_fingerprint_count']} users from browser"

    embed = {
        "title": "🔐 New Web Verification",
        "description": f"**Risk Assessment:** {alt_status}",
        "color": embed_color,
        "fields": [
            {"name": "👤 Username", "value": f"{username}", "inline": True},
            {"name": "🆔 User ID", "value": f"`{user_id}`", "inline": True},
            {"name": "📧 Email", "value": f"{email}\n{email_verified}", "inline": False},
            
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**Account Information**", "inline": False},
            {"name": "📅 Account Age", "value": f"{account_age['age_formatted']}\nCreated: {account_age['created_at'][:10]}", "inline": True},
            {"name": "💎 Nitro Status", "value": nitro_status, "inline": True},
            {"name": "🏅 Badges", "value": badges_text, "inline": True},
            {"name": "🖼️ Customization", "value": f"Avatar: {has_avatar}\nBanner: {has_banner}", "inline": True},
            {"name": "🌐 Servers", "value": mutual_text, "inline": True},
            {"name": "🔄 Previous Checks", "value": duplicate_status, "inline": True},
            
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**Security Analysis**", "inline": False},
            {"name": "🔍 Alt Detection", "value": alt_status + (f"\n{', '.join(alt_detection['flags'][:4])}" if alt_detection['flags'] else ""), "inline": True},
            {"name": "🛡️ VPN/Proxy", "value": f"{vpn_status}\nRisk: {vpn_check['risk_score']}%", "inline": True},
            {"name": "⚠️ Suspicious Patterns", "value": pattern_text, "inline": True},
            
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**Connection Details**", "inline": False},
            {"name": "🌐 IP Address", "value": f"`{ip_info.get('ip', 'Unknown')}`", "inline": True},
            {"name": "🏢 ISP", "value": ip_info.get('isp', 'Unknown')[:50], "inline": True},
            {"name": "🔒 Fingerprint", "value": f"`{fingerprint_info['fingerprint']}`", "inline": True},
            {"name": "📍 Location", "value": f"{ip_info.get('city', 'Unknown')}, {ip_info.get('region', 'Unknown')}\n{ip_info.get('country', 'Unknown')}", "inline": False},
            {"name": "🖥️ User Agent", "value": f"`{user_agent_short}`", "inline": False},
            {"name": "⏰ Verified at (UTC)", "value": now, "inline": False},
        ],
        "footer": {"text": f"Enchanted • Web Verification • Service: {vpn_check['service']}"},
    }

    payload = {"embeds": [embed]}
    if avatar_url:
        payload["embeds"][0]["thumbnail"] = {"url": avatar_url}

    try:
        response = requests.post(RC_LOGS_WEBHOOK, data=json.dumps(payload), headers={"Content-Type": "application/json"})
        if response.status_code != 204:
            print(f"Webhook failed with status {response.status_code}: {response.text}")
    except Exception as e:
        print(f"Failed to send webhook: {e}")


# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return redirect("/verify")


@app.route("/verify")
def verify_page():
    oauth_url = build_oauth_url()
    return render_template_string(
        VERIFY_PAGE_HTML,
        site_name=SITE_NAME,
        oauth_url=oauth_url
    )


@app.route("/callback")
def oauth_callback():
    # Generate browser fingerprint
    fingerprint_info = generate_browser_fingerprint(request) if ENABLE_FINGERPRINTING else {'fingerprint': 'disabled'}
    
    # Collect IP and browser information
    ip_address = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Check for VPN/Proxy
    vpn_check = check_vpn_proxy(ip_address)
    
    # Block if VPN detected and blocking is enabled
    if vpn_check['blocked']:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message="VPN/Proxy detected. Please disable your VPN and try again."
        )
    
    location_data = get_ip_location(ip_address)
    
    ip_info = {
        'ip': ip_address,
        'user_agent': user_agent,
        'country': location_data['country'],
        'city': location_data['city'],
        'region': location_data['region'],
        'isp': location_data['isp'],
        'timezone': location_data['timezone'],
        'vpn_detected': vpn_check['is_vpn'] or vpn_check['is_proxy']
    }
    
    error = request.args.get("error")
    if error:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message=f"Discord returned an error: {error}"
        )

    code = request.args.get("code")
    if not code:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message="Missing OAuth code. Please try again."
        )

    token_data = exchange_code(code)
    if not token_data:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message="Could not exchange OAuth code. Please try again."
        )

    access_token = token_data.get("access_token")
    if not access_token:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message="No access token received from Discord."
        )

    user = get_discord_user(access_token)
    if not user:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message="Failed to fetch your Discord account. Please try again."
        )

    # Calculate account age
    user_id = user.get("id", "Unknown")
    account_age = calculate_account_age(user_id)
    
    # Check minimum account age requirement
    if MIN_ACCOUNT_AGE_DAYS > 0 and account_age['age_days'] < MIN_ACCOUNT_AGE_DAYS:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message=f"Your account must be at least {MIN_ACCOUNT_AGE_DAYS} days old to verify. Your account is {account_age['age_days']} days old."
        )
    
    # Check for duplicate verification
    duplicate_check = check_duplicate_verification(
        user_id, 
        ip_address, 
        fingerprint_info['fingerprint']
    ) if ENABLE_DUPLICATE_DETECTION else {
        'is_duplicate': False,
        'previous_verifications': 0,
        'same_ip_count': 0,
        'same_fingerprint_count': 0,
        'suspicious_pattern': False
    }
    
    # Get user's guilds and check mutual servers
    guilds = get_user_guilds(access_token)
    guilds_info = check_mutual_servers(guilds)
    
    # Get account badges
    badges = get_account_flags(user)
    
    # Enhanced alt detection with all new data
    alt_detection = detect_alt_account(user, account_age, ip_info, duplicate_check, guilds_info, badges)
    
    # Block if risk score is too high
    if alt_detection['risk_score'] > MAX_ALT_RISK_SCORE:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message=f"Verification failed. Your account triggered our security system (Risk: {alt_detection['risk_score']}%). Please contact an administrator."
        )
    
    # Save verification to database
    if ENABLE_DUPLICATE_DETECTION:
        save_verification(user_id, ip_address, fingerprint_info['fingerprint'], user.get('email', ''))

    # Send comprehensive verification log
    send_verification_log(user, ip_info, account_age, alt_detection, vpn_check, 
                         duplicate_check, guilds_info, fingerprint_info, badges)

    username = user.get('username', 'Unknown')
    discriminator = user.get('discriminator', '0')
    if discriminator != '0':
        username = f"{username}#{discriminator}"

    return render_template_string(
        SUCCESS_PAGE_HTML,
        site_name=SITE_NAME,
        username=username,
        user_id=user_id
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
