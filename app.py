import os
import json
import urllib.parse
import hashlib
import re
from datetime import datetime, timezone
from collections import defaultdict

import requests
from flask import Flask, redirect, request, url_for, render_template_string, jsonify

try:
    from user_agents import parse as parse_ua
except ImportError:
    print("⚠️ WARNING: user_agents not installed. Install with: pip install user-agents")
    def parse_ua(ua_string):
        return type('obj', (object,), {
            'browser': type('obj', (object,), {'family': 'Unknown', 'version_string': ''})(),
            'os': type('obj', (object,), {'family': 'Unknown', 'version_string': ''})(),
            'device': type('obj', (object,), {'family': 'Unknown'})(),
            'is_mobile': False,
            'is_tablet': False,
            'is_pc': True,
            'is_bot': False
        })()

app = Flask(__name__)

# ---------------- CONFIG ----------------
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
RC_LOGS_WEBHOOK = os.getenv("RC_LOGS_WEBHOOK")
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
GUILD_ID = os.getenv("DISCORD_GUILD_ID")
MEMBER_ROLE_ID = "1437971141925929139"
PULL_SECRET = os.getenv("PULL_SECRET", "change-this-secret")

OAUTH_SCOPE = "identify email guilds guilds.members.read connections guilds.join"
DISCORD_API_BASE = "https://discord.com/api"
SITE_NAME = "Enchanted Verification"

VPN_BLOCK_THRESHOLD = 75
BLOCK_VPNS = True

# In-memory tracking
ip_usage_tracker = defaultdict(list)
email_domain_tracker = defaultdict(int)
fingerprint_tracker = defaultdict(list)
verified_users = {}

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
      h1 { margin-bottom: 8px; }
      p { margin-bottom: 24px; color: #d0c6e8; }
      a.button {
        display: inline-block;
        padding: 12px 24px;
        border-radius: 999px;
        text-decoration: none;
        background: #5865F2;
        color: white;
        font-weight: 600;
      }
      a.button:hover { opacity: 0.9; }
      .privacy { font-size: 12px; color: #888; margin-top: 16px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>{{ site_name }}</h1>
      <p>Click the button below to verify your Discord account.</p>
      <a class="button" href="{{ oauth_url }}">Click to verify</a>
      <p class="privacy">By verifying, you agree to connect your Discord account. We collect comprehensive account, device, and connection information for security purposes.</p>
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
      h1 { margin-bottom: 8px; }
      p { margin-bottom: 16px; color: #d0c6e8; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Verification complete ✅</h1>
      <p>You have been added to the server and assigned the Member role!</p>
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

def get_client_ip():
    """Get the user's IP address, accounting for proxies"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip


def parse_user_agent(ua_string):
    """Parse user agent into detailed components"""
    try:
        user_agent = parse_ua(ua_string)
        return {
            'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
            'os': f"{user_agent.os.family} {user_agent.os.version_string}",
            'device': user_agent.device.family,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'is_bot': user_agent.is_bot
        }
    except Exception as e:
        print(f"Error parsing user agent: {e}")
        return {
            'browser': 'Unknown',
            'os': 'Unknown',
            'device': 'Unknown',
            'is_mobile': False,
            'is_tablet': False,
            'is_pc': False,
            'is_bot': False
        }


def check_vpn_proxy(ip_address):
    """Enhanced VPN/Proxy detection with multiple services"""
    result = {
        'is_vpn': False,
        'is_proxy': False,
        'is_tor': False,
        'is_datacenter': False,
        'risk_score': 0,
        'service': 'None',
        'blocked': False,
        'details': []
    }
    
    # IPHub check
    try:
        response = requests.get(
            f"http://v2.api.iphub.info/ip/{ip_address}", 
            headers={'X-Key': os.getenv('IPHUB_API_KEY', 'free')},
            timeout=3
        )
        
        if response.status_code == 200:
            data = response.json()
            block_type = data.get('block', 0)
            
            if block_type == 1:
                result['is_vpn'] = True
                result['is_proxy'] = True
                result['risk_score'] = 90
                result['service'] = 'IPHub'
                result['details'].append(f"IPHub: VPN/Proxy (block={block_type})")
            elif block_type == 2:
                result['is_tor'] = True
                result['risk_score'] = 100
                result['service'] = 'IPHub'
                result['details'].append("IPHub: TOR Exit Node")
    except Exception as e:
        result['details'].append(f"IPHub error: {str(e)[:50]}")
    
    # ip-api.com enhanced check
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=status,proxy,hosting,mobile,query,isp,org,as", 
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('proxy'):
                result['is_proxy'] = True
                result['risk_score'] = max(result['risk_score'], 70)
                result['details'].append("ip-api: Proxy detected")
            if data.get('hosting'):
                result['is_datacenter'] = True
                result['risk_score'] = max(result['risk_score'], 60)
                result['details'].append(f"ip-api: Datacenter/Hosting ({data.get('org', 'Unknown')})")
            if data.get('mobile'):
                result['details'].append("ip-api: Mobile connection")
    except Exception as e:
        result['details'].append(f"ip-api error: {str(e)[:50]}")
    
    # Check IP against known VPN ranges
    if is_vpn_range(ip_address):
        result['is_vpn'] = True
        result['risk_score'] = max(result['risk_score'], 85)
        result['details'].append("IP in known VPN range")
    
    # Determine if should block
    if BLOCK_VPNS and result['risk_score'] >= VPN_BLOCK_THRESHOLD:
        result['blocked'] = True
    
    return result


def is_vpn_range(ip):
    """Check if IP is in known VPN/proxy ranges"""
    vpn_ranges = ['185.220.', '185.100.']
    return any(ip.startswith(prefix) for prefix in vpn_ranges)


def get_ip_location(ip_address):
    """Enhanced location information from IP"""
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query",
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'zip': data.get('zip', 'Unknown'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', 'Unknown'),
                    'asname': data.get('asname', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'is_mobile': data.get('mobile', False),
                    'is_proxy': data.get('proxy', False),
                    'is_hosting': data.get('hosting', False)
                }
    except Exception as e:
        print(f"Failed to get IP location: {e}")
    
    return {
        'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown',
        'region': 'Unknown', 'zip': 'Unknown', 'latitude': None, 'longitude': None,
        'isp': 'Unknown', 'org': 'Unknown', 'as': 'Unknown', 'asname': 'Unknown',
        'timezone': 'Unknown', 'is_mobile': False, 'is_proxy': False, 'is_hosting': False
    }


def calculate_account_age(user_id):
    """Calculate Discord account age from snowflake ID"""
    try:
        discord_epoch = 1420070400000
        timestamp = ((int(user_id) >> 22) + discord_epoch) / 1000
        created_at = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        age = datetime.now(timezone.utc) - created_at
        
        days = age.days
        hours = age.seconds // 3600
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
            'created_at_unix': int(timestamp),
            'age_days': days,
            'age_hours': (days * 24) + hours,
            'age_formatted': ' '.join(age_parts),
            'is_new': days < 30,
            'is_very_new': days < 7,
            'is_suspicious': days < 3,
            'is_fresh': hours < 24
        }
    except Exception as e:
        return {
            'created_at': 'Unknown', 'created_at_unix': 0, 'age_days': 0,
            'age_hours': 0, 'age_formatted': 'Unknown', 'is_new': False,
            'is_very_new': False, 'is_suspicious': False, 'is_fresh': False
        }


def analyze_email_domain(email):
    """Analyze email domain for suspicious patterns"""
    if not email or '@' not in email:
        return {'domain': 'Unknown', 'is_disposable': False, 'is_suspicious': False, 'provider': 'Unknown', 'usage_count': 0}
    
    domain = email.split('@')[1].lower()
    
    disposable_domains = {
        'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
        'throwaway.email', 'temp-mail.org', 'getnada.com', 'maildrop.cc'
    }
    
    trusted_providers = {
        'gmail.com': 'Google', 'outlook.com': 'Microsoft', 'hotmail.com': 'Microsoft',
        'yahoo.com': 'Yahoo', 'icloud.com': 'Apple', 'protonmail.com': 'ProtonMail',
        'aol.com': 'AOL', 'mail.com': 'Mail.com'
    }
    
    is_disposable = domain in disposable_domains
    provider = trusted_providers.get(domain, 'Other')
    
    is_suspicious = (
        is_disposable or
        len(domain) < 4 or
        domain.count('.') > 2 or
        any(char.isdigit() for char in domain.split('.')[0])
    )
    
    email_domain_tracker[domain] += 1
    
    return {
        'domain': domain,
        'is_disposable': is_disposable,
        'is_suspicious': is_suspicious,
        'provider': provider,
        'usage_count': email_domain_tracker[domain]
    }


def check_duplicate_accounts(user_id, ip_address, email):
    """Check for duplicate accounts from same IP or email domain"""
    ip_usage_tracker[ip_address].append(user_id)
    
    accounts_from_ip = len(set(ip_usage_tracker[ip_address]))
    
    return {
        'accounts_from_ip': accounts_from_ip,
        'is_shared_ip': accounts_from_ip > 1,
        'ip_usage_list': list(set(ip_usage_tracker[ip_address]))[:5]
    }


def detect_alt_account(user, account_age, ip_info, email_analysis, duplicate_check, ua_info):
    """Enhanced alt account detection with more factors"""
    risk_score = 0
    flags = []
    
    # Account age checks
    if account_age['is_fresh']:
        risk_score += 50
        flags.append("🚨 Account less than 24 hours old")
    elif account_age['is_suspicious']:
        risk_score += 40
        flags.append("⚠️ Account less than 3 days old")
    elif account_age['is_very_new']:
        risk_score += 25
        flags.append("Account less than 7 days old")
    elif account_age['is_new']:
        risk_score += 15
        flags.append("Account less than 30 days old")
    
    # Profile customization
    if not user.get('avatar'):
        risk_score += 15
        flags.append("No custom avatar")
    if not user.get('banner'):
        risk_score += 5
        flags.append("No custom banner")
    # Bio isn't provided by /users/@me for most accounts, so we don't use it
    # in the risk calculation to avoid false "no bio" flags.
    # if not user.get('bio'):
    #     risk_score += 5
    #     flags.append("No bio")
    
    # Username analysis
    username = user.get('username', '')
    if any(char.isdigit() for char in username[-4:]):
        risk_score += 10
        flags.append("Numeric username suffix")
    if len(username) < 4:
        risk_score += 8
        flags.append("Very short username")
    if re.search(r'(alt|fake|temp|test|throw)', username.lower()):
        risk_score += 20
        flags.append("Suspicious username keywords")
    
    # Email verification
    if not user.get('verified', False):
        risk_score += 25
        flags.append("Email not verified")
    
    # Email domain analysis
    if email_analysis['is_disposable']:
        risk_score += 35
        flags.append("🚨 Disposable email domain")
    if email_analysis['is_suspicious']:
        risk_score += 15
        flags.append("Suspicious email domain")
    if email_analysis['usage_count'] > 3:
        risk_score += 20
        flags.append(f"Email domain used {email_analysis['usage_count']} times")
    
    # VPN/Proxy on new account
    if ip_info.get('vpn_detected') and account_age['is_new']:
        risk_score += 30
        flags.append("VPN on new account")
    
    # Duplicate account detection
    if duplicate_check['is_shared_ip']:
        risk_score += 25
        flags.append(f"IP used by {duplicate_check['accounts_from_ip']} accounts")
    
    # Bot detection
    if ua_info.get('is_bot'):
        risk_score += 40
        flags.append("🤖 Bot user agent detected")
    
    # Mobile device on fresh account (less suspicious)
    if ua_info.get('is_mobile') and not account_age['is_fresh']:
        risk_score = max(0, risk_score - 5)
    
    # Nitro status (reduces risk significantly)
    if user.get('premium_type'):
        risk_score = max(0, risk_score - 25)
        flags.append("✅ Has Nitro (reduces risk)")
    
    # Public flags (badges)
    public_flags = user.get('public_flags', 0)
    if public_flags > 0:
        risk_score = max(0, risk_score - 15)
        flags.append("Has Discord badges")
    
    # Cap risk score
    risk_score = min(risk_score, 100)
    
    return {
        'risk_score': risk_score,
        'flags': flags,
        'is_likely_alt': risk_score >= 60,
        'is_high_risk': risk_score >= 75,
        'risk_level': 'Critical' if risk_score >= 85 else 'High' if risk_score >= 70 else 'Medium' if risk_score >= 40 else 'Low'
    }


def get_discord_guilds(access_token):
    """Get user's Discord servers"""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        r = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=headers)
        if r.status_code == 200:
            guilds = r.json()
            return {
                'count': len(guilds),
                'names': [g.get('name', 'Unknown')[:30] for g in guilds[:10]],
                'owned': len([g for g in guilds if g.get('owner', False)])
            }
    except Exception as e:
        print(f"Failed to get guilds: {e}")
    return {'count': 0, 'names': [], 'owned': 0}


def get_discord_connections(access_token):
    """Get user's connected accounts"""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        r = requests.get(f"{DISCORD_API_BASE}/users/@me/connections", headers=headers)
        if r.status_code == 200:
            connections = r.json()
            return {
                'count': len(connections),
                'types': [c.get('type', 'unknown') for c in connections],
                'verified': len([c for c in connections if c.get('verified', False)])
            }
    except Exception as e:
        print(f"Failed to get connections: {e}")
    return {'count': 0, 'types': [], 'verified': 0}


def decode_public_flags(flags):
    """Decode Discord public flags (badges)"""
    flag_names = {
        1 << 0: 'Discord Employee',
        1 << 1: 'Partnered Server Owner',
        1 << 2: 'HypeSquad Events',
        1 << 3: 'Bug Hunter Level 1',
        1 << 6: 'HypeSquad Bravery',
        1 << 7: 'HypeSquad Brilliance',
        1 << 8: 'HypeSquad Balance',
        1 << 9: 'Early Supporter',
        1 << 14: 'Bug Hunter Level 2',
        1 << 17: 'Verified Bot Developer',
        1 << 18: 'Early Verified Bot Developer',
        1 << 22: 'Active Developer'
    }
    
    badges = []
    for flag, name in flag_names.items():
        if flags & flag:
            badges.append(name)
    
    return badges if badges else ['None']


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
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(f"{DISCORD_API_BASE}/oauth2/token", data=data, headers=headers)
    if r.status_code != 200:
        print("Token exchange failed:", r.text)
        return None
    return r.json()


def get_discord_user(access_token: str) -> dict | None:
    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(f"{DISCORD_API_BASE}/users/@me", headers=headers)
    if r.status_code != 200:
        print("Get user failed:", r.text)
        return None
    return r.json()


def add_user_to_guild(access_token: str, user_id: str) -> bool:
    """Add user to the Discord server using bot token"""
    if not BOT_TOKEN or not GUILD_ID:
        print("Missing BOT_TOKEN or GUILD_ID")
        return False
    
    url = f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/members/{user_id}"
    headers = {
        "Authorization": f"Bot {BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "access_token": access_token
    }
    
    try:
        r = requests.put(url, headers=headers, json=data)
        if r.status_code in [200, 201, 204]:
            print(f"✅ Successfully added user {user_id} to guild")
            return True
        else:
            print(f"Failed to add user to guild: {r.status_code} - {r.text}")
            return False
    except Exception as e:
        print(f"Error adding user to guild: {e}")
        return False


def assign_member_role(user_id: str) -> bool:
    """Assign the member role to the user"""
    if not BOT_TOKEN or not GUILD_ID:
        print("Missing BOT_TOKEN or GUILD_ID")
        return False
    
    url = f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/members/{user_id}/roles/{MEMBER_ROLE_ID}"
    headers = {
        "Authorization": f"Bot {BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        r = requests.put(url, headers=headers)
        if r.status_code in [200, 204]:
            print(f"✅ Successfully assigned member role to user {user_id}")
            return True
        else:
            print(f"Failed to assign role: {r.status_code} - {r.text}")
            return False
    except Exception as e:
        print(f"Error assigning role: {e}")
        return False


def pull_all_verified_users():
    """Pull all verified users back into the server"""
    results = {
        "success": [],
        "failed": [],
        "role_assigned": [],
        "role_failed": []
    }
    
    for user_id, user_data in verified_users.items():
        access_token = user_data.get("access_token")
        
        if not access_token:
            results["failed"].append({"user_id": user_id, "reason": "No access token"})
            continue
        
        # Try to add user to guild
        added = add_user_to_guild(access_token, user_id)
        
        if added:
            results["success"].append(user_id)
            
            # Try to assign role
            role_assigned = assign_member_role(user_id)
            if role_assigned:
                results["role_assigned"].append(user_id)
            else:
                results["role_failed"].append(user_id)
        else:
            results["failed"].append({"user_id": user_id, "reason": "Failed to add to guild"})
    
    return results


def send_verification_log(user, ip_info, account_age, alt_detection, vpn_check, email_analysis, 
                         duplicate_check, ua_info, guilds_info, connections_info):
    """Send comprehensive verification embed to webhook (Discord-safe: <= 25 fields)"""
    if not RC_LOGS_WEBHOOK:
        print("❌ No RC_LOGS_WEBHOOK configured - cannot send log")
        return False

    try:
        username = user.get('username', 'Unknown')
        discriminator = user.get('discriminator', '0')
        if discriminator != '0':
            username = f"{username}#{discriminator}"
        
        user_id = user.get("id", "Unknown")
        avatar_hash = user.get("avatar")
        email = user.get("email", "Not provided")
        email_verified = "✅ Verified" if user.get("verified", False) else "❌ Not verified"
        
        premium_type = user.get("premium_type")
        nitro_status = {0: "None", 1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}.get(premium_type, "None")
        
        has_banner = "✅ Yes" if user.get("banner") else "❌ No"
        has_avatar = "✅ Yes" if avatar_hash else "❌ No (Default)"
        # /users/@me usually doesn't include the profile bio, so we mark it as unavailable
        has_bio = "ℹ️ Not available via API"
        
        public_flags = user.get('public_flags', 0)
        badges = decode_public_flags(public_flags)
        badge_str = ', '.join(badges[:3]) if badges != ['None'] else 'None'

        avatar_url = None
        if avatar_hash and user_id:
            avatar_url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png?size=256"

        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        user_agent_short = ip_info['user_agent'][:150] if ip_info['user_agent'] else 'Unknown'

        # Color: themed + risk hint (but within same hex base)
        base_color = int("1c0333", 16)

        # VPN status text
        vpn_status = "✅ Clean"
        if vpn_check['is_tor']:
            vpn_status = "🔴 TOR Exit Node"
        elif vpn_check['is_vpn']:
            vpn_status = "🟡 VPN Detected"
        elif vpn_check['is_proxy']:
            vpn_status = "🟠 Proxy Detected"
        elif vpn_check['is_datacenter']:
            vpn_status = "🟤 Datacenter IP"
        if vpn_check['blocked']:
            vpn_status += " (BLOCKED)"

        # Alt detection summary
        risk_emoji = (
            "🔴" if alt_detection['is_high_risk']
            else "🟠" if alt_detection['is_likely_alt']
            else "🟡" if alt_detection['risk_score'] >= 40
            else "🟢"
        )
        alt_status = f"{risk_emoji} {alt_detection['risk_level']} Risk ({alt_detection['risk_score']}%)"

        # Build a compact, Discord-safe embed (<=25 fields)
        fields = [
            # 1–5: Basic account
            {"name": "Username", "value": f"`{username}`", "inline": True},
            {"name": "User ID", "value": f"`{user_id}`", "inline": True},
            {"name": "Badges (public flags)", "value": badge_str[:100], "inline": True},


            # 6–8: Email
            {"name": "Email", "value": f"{email}\n{email_verified}", "inline": True},
            {"name": "Email Domain", "value": f"{email_analysis['domain']} ({email_analysis['provider']})", "inline": True},
            {"name": "Domain Usage", "value": f"Used {email_analysis['usage_count']} time(s)", "inline": True},

            # 9–12: Account stats
            {
                "name": "Account Age",
                "value": f"{account_age['age_formatted']}\nCreated: <t:{account_age['created_at_unix']}:R>",
                "inline": True,
            },
            {"name": "Nitro Status", "value": nitro_status, "inline": True},
            {
                "name": "Profile Customization",
                "value": f"Avatar: {has_avatar}\nBanner: {has_banner}\nBio: {has_bio}",
                "inline": True,
            },
            {
                "name": "Servers & Linked Accounts",
                "value": (
                    f"Servers: {guilds_info['count']} (Owned: {guilds_info['owned']})\n"
                    f"Linked accounts: {connections_info['count']} (Verified: {connections_info['verified']})"
                ),
                "inline": False,
            },

            # 13–15: Risk
            {"name": "Risk Level", "value": alt_status, "inline": True},
            {
                "name": "Risk Flags",
                "value": '\n'.join(f"• {flag}" for flag in alt_detection['flags'][:8]) if alt_detection['flags'] else "✅ No flags",
                "inline": False,
            },
            {
                "name": "Public Flags",
                "value": f"Raw: `{public_flags}`\nFlag Count: {0 if badges == ['None'] else len(badges)}",
                "inline": True,
            },

            # 16–19: Network / IP
            {"name": "VPN / Proxy Status", "value": f"{vpn_status}\nRisk: {vpn_check['risk_score']}%", "inline": True},
            {
                "name": "IP Reuse",
                "value": f"Accounts from IP: {duplicate_check['accounts_from_ip']}\n"
                         f"{'⚠️ Shared IP' if duplicate_check['is_shared_ip'] else '✅ Unique IP'}",
                "inline": True,
            },
            {"name": "IP Address", "value": f"`{ip_info.get('ip', 'Unknown')}`", "inline": True},
            {
                "name": "Location",
                "value": (
                    f"City: {ip_info.get('city', 'Unknown')}\n"
                    f"Region: {ip_info.get('region', 'Unknown')}\n"
                    f"Country: {ip_info.get('country', 'Unknown')} ({ip_info.get('country_code', '??')})\n"
                    f"Timezone: {ip_info.get('timezone', 'Unknown')}"
                ),
                "inline": False,
            },

            # 20–22: Device / UA
            {
                "name": "Device & OS",
                "value": f"Device: {ua_info.get('device', 'Unknown')}\nOS: {ua_info.get('os', 'Unknown')}",
                "inline": True,
            },
            {
                "name": "Browser",
                "value": ua_info.get('browser', 'Unknown')[:50],
                "inline": True,
            },
            {
                "name": "User Agent",
                "value": f"`{user_agent_short}`",
                "inline": False,
            },

            # 23–25: Extra connection + time
            {
                "name": "Connection Type",
                "value": (
                    "📱 Mobile Network" if ip_info.get('is_mobile')
                    else "🏢 Datacenter" if ip_info.get('is_hosting')
                    else "🏠 Residential"
                ),
                "inline": True,
            },
            {
                "name": "Coordinates",
                "value": (
                    f"Lat: {ip_info.get('latitude', 'N/A')}\nLon: {ip_info.get('longitude', 'N/A')}"
                    if ip_info.get('latitude') is not None else "Not available"
                ),
                "inline": True,
            },
            {
                "name": "Timestamps",
                "value": (
                    f"Verification: {now}\n"
                    f"Created: <t:{account_age['created_at_unix']}:F>\n"
                    f"Age: {account_age['age_hours']} hours"
                ),
                "inline": False,
            },
        ]

        embed = {
            "title": "🔐 Web Verification",
            "description": f"**Risk Assessment:** {alt_status}",
            "color": base_color,
            "fields": fields,
            "footer": {
                "text": f"Enchanted Verification • Flags: {len(alt_detection['flags'])}"
            },
            "timestamp": now,
        }

        if avatar_url:
            embed["thumbnail"] = {"url": avatar_url}

        payload = {"embeds": [embed]}

        print(f"📤 Sending webhook to: {RC_LOGS_WEBHOOK[:50]}...")
        response = requests.post(
            RC_LOGS_WEBHOOK,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )

        if response.status_code == 204:
            print(f"✅ Verification logged for {username} (Risk: {alt_detection['risk_score']}%)")
            return True
        else:
            print(f"❌ Webhook failed with status {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Failed to send webhook: {e}")
        import traceback
        traceback.print_exc()
        return False

def send_pull_notification(pull_results):
    """Send a notification to the webhook about the pull operation"""
    if not RC_LOGS_WEBHOOK:
        return
    
    try:
        stats = pull_results["stats"]
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        
        # Determine color based on success rate
        success_rate = (stats["added_to_server"] / stats["total"] * 100) if stats["total"] > 0 else 0
        if success_rate >= 90:
            color = 0x00ff00  # Green
        elif success_rate >= 70:
            color = 0xffcc00  # Yellow
        else:
            color = 0xff0000  # Red
        
        embed = {
            "title": "🔄 Mass Pull Operation Completed",
            "description": f"Attempted to pull {stats['total']} verified users back into the server",
            "color": color,
            "fields": [
                {"name": "✅ Successfully Added", "value": str(stats["added_to_server"]), "inline": True},
                {"name": "❌ Failed", "value": str(stats["failed"]), "inline": True},
                {"name": "📊 Success Rate", "value": f"{success_rate:.1f}%", "inline": True},
                {"name": "👤 Roles Assigned", "value": str(stats["role_assigned"]), "inline": True},
                {"name": "⚠️ Role Assignment Failed", "value": str(stats["role_failed"]), "inline": True},
                {"name": "🔢 Total Verified Users", "value": str(stats["total"]), "inline": True}
            ],
            "footer": {"text": "Enchanted • Mass Pull Operation"},
            "timestamp": now
        }
        
        # Add failed users if any (limited to first 10)
        if pull_results["details"]["failed"]:
            failed_list = pull_results["details"]["failed"][:10]
            failed_text = "\n".join(f"• {item['user_id']}: {item['reason']}" for item in failed_list)
            if len(pull_results["details"]["failed"]) > 10:
                failed_text += f"\n... and {len(pull_results['details']['failed']) - 10} more"
            embed["fields"].append({
                "name": "Failed Users", 
                "value": failed_text, 
                "inline": False
            })
        
        payload = {"embeds": [embed]}
        requests.post(RC_LOGS_WEBHOOK, json=payload, timeout=10)
    except Exception as e:
        print(f"Failed to send pull notification: {e}")


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
    # Collect comprehensive client information
    ip_address = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Parse user agent
    ua_info = parse_user_agent(user_agent)
    
    # Check for VPN/Proxy
    vpn_check = check_vpn_proxy(ip_address)
    
    # Block if VPN detected and blocking is enabled
    if vpn_check['blocked']:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message=f"VPN/Proxy detected. Please disable your VPN and try again. (Risk Score: {vpn_check['risk_score']}%)"
        )
    
    # Get enhanced location data
    location_data = get_ip_location(ip_address)
    
    ip_info = {
        'ip': ip_address,
        'user_agent': user_agent,
        'country': location_data['country'],
        'country_code': location_data['country_code'],
        'city': location_data['city'],
        'region': location_data['region'],
        'zip': location_data['zip'],
        'isp': location_data['isp'],
        'org': location_data['org'],
        'asname': location_data['asname'],
        'timezone': location_data['timezone'],
        'latitude': location_data['latitude'],
        'longitude': location_data['longitude'],
        'is_mobile': location_data['is_mobile'],
        'is_hosting': location_data['is_hosting'],
        'vpn_detected': vpn_check['is_vpn'] or vpn_check['is_proxy']
    }
    
    # Handle OAuth errors
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

    # Exchange code for token
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

    # Get user information
    user = get_discord_user(access_token)
    if not user:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message="Failed to fetch your Discord account. Please try again."
        )

    user_id = user.get("id", "Unknown")
    email = user.get("email", "")
    
    # Store verified user data for /pull functionality
    verified_users[user_id] = {
        "access_token": access_token,
        "username": user.get("username"),
        "verified_at": datetime.utcnow().isoformat()
    }
    
    # Get additional data
    guilds_info = get_discord_guilds(access_token)
    connections_info = get_discord_connections(access_token)
    
    # Analyze account
    account_age = calculate_account_age(user_id)
    email_analysis = analyze_email_domain(email)
    duplicate_check = check_duplicate_accounts(user_id, ip_address, email)
    
    # Detect alt account with enhanced factors
    alt_detection = detect_alt_account(
        user, account_age, ip_info, email_analysis, 
        duplicate_check, ua_info
    )

    # Send comprehensive verification log
    webhook_sent = send_verification_log(
        user, ip_info, account_age, alt_detection, vpn_check,
        email_analysis, duplicate_check, ua_info, guilds_info, connections_info
    )
    
    if webhook_sent:
        print("✅ Webhook log sent successfully")
    else:
        print("❌ Webhook log failed to send")

    # Add user to guild and assign role
    guild_added = add_user_to_guild(access_token, user_id)
    role_assigned = False
    
    if guild_added:
        print(f"✅ User {user_id} added to guild")
        # Assign member role
        role_assigned = assign_member_role(user_id)
        if role_assigned:
            print(f"✅ Member role assigned to {user_id}")
        else:
            print(f"⚠️ Failed to assign member role to {user_id}")
    else:
        print(f"⚠️ Failed to add user {user_id} to guild")

    # Build username display
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


@app.route("/health")
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "ok", "service": "discord-verification"}), 200


@app.route("/config")
def config_check():
    """Debug endpoint to check configuration"""
    return jsonify({
        "CLIENT_ID": "SET" if CLIENT_ID else "NOT SET",
        "CLIENT_SECRET": "SET" if CLIENT_SECRET else "NOT SET",
        "REDIRECT_URI": REDIRECT_URI if REDIRECT_URI else "NOT SET",
        "BOT_TOKEN": "SET" if BOT_TOKEN else "NOT SET",
        "GUILD_ID": GUILD_ID if GUILD_ID else "NOT SET",
        "RC_LOGS_WEBHOOK": "SET" if RC_LOGS_WEBHOOK else "NOT SET",
        "WEBHOOK_PREVIEW": RC_LOGS_WEBHOOK[:60] + "..." if RC_LOGS_WEBHOOK else "NOT SET",
        "PULL_SECRET": "SET" if PULL_SECRET else "NOT SET",
        "MEMBER_ROLE_ID": MEMBER_ROLE_ID
    }), 200


@app.route("/test-webhook")
def test_webhook():
    """Test webhook endpoint to verify it's working"""
    print("=" * 60)
    print("🧪 WEBHOOK TEST STARTED")
    print("=" * 60)
    
    if not RC_LOGS_WEBHOOK:
        print("❌ RC_LOGS_WEBHOOK is NOT SET in environment variables")
        return jsonify({
            "error": "RC_LOGS_WEBHOOK not configured",
            "webhook_set": False,
            "help": "Set the RC_LOGS_WEBHOOK environment variable in your Render dashboard"
        }), 500
    
    print(f"✅ Webhook URL is set")
    print(f"📍 Webhook URL: {RC_LOGS_WEBHOOK[:70]}...")
    print(f"🔗 Full length: {len(RC_LOGS_WEBHOOK)} characters")
    
    try:
        # Create a simple test embed
        test_embed = {
            "title": "🧪 Webhook Test",
            "description": "This is a test message to verify the webhook is working correctly.",
            "color": 0x00ff00,
            "fields": [
                {"name": "Status", "value": "✅ Webhook is configured", "inline": True},
                {"name": "Timestamp", "value": datetime.utcnow().isoformat(), "inline": True},
                {"name": "Test ID", "value": f"{datetime.utcnow().timestamp()}", "inline": False}
            ],
            "footer": {"text": "Enchanted Verification System • Test Message"}
        }
        
        payload = {"embeds": [test_embed]}
        
        print(f"📦 Payload created:")
        print(json.dumps(payload, indent=2)[:500])
        print(f"\n🚀 Sending POST request to webhook...")
        
        response = requests.post(
            RC_LOGS_WEBHOOK,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"📨 Response received:")
        print(f"   Status Code: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")
        
        if response.status_code == 204:
            print("✅ SUCCESS! Webhook message sent successfully!")
            return jsonify({
                "success": True,
                "status_code": response.status_code,
                "webhook_set": True,
                "webhook_url_preview": RC_LOGS_WEBHOOK[:70] + "...",
                "message": "Webhook test successful! Check your Discord channel."
            }), 200
        else:
            print(f"❌ FAILED with status {response.status_code}")
            print(f"   Response body: {response.text}")
            return jsonify({
                "success": False,
                "status_code": response.status_code,
                "webhook_set": True,
                "webhook_url_preview": RC_LOGS_WEBHOOK[:70] + "...",
                "response_text": response.text,
                "error": "Webhook returned non-204 status code"
            }), 200
        
    except requests.exceptions.Timeout:
        print("❌ TIMEOUT: Request took longer than 10 seconds")
        return jsonify({
            "error": "Request timeout",
            "webhook_set": True,
            "message": "The webhook request timed out after 10 seconds"
        }), 500
        
    except requests.exceptions.ConnectionError as e:
        print(f"❌ CONNECTION ERROR: {str(e)}")
        return jsonify({
            "error": "Connection error",
            "webhook_set": True,
            "message": str(e)
        }), 500
        
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": str(e),
            "error_type": type(e).__name__,
            "webhook_set": True,
            "traceback": traceback.format_exc()
        }), 500
    finally:
        print("=" * 60)
        print("🧪 WEBHOOK TEST ENDED")
        print("=" * 60)


@app.route("/verify-webhook")
def verify_webhook_url():
    """Verify the webhook URL format and test connectivity"""
    if not RC_LOGS_WEBHOOK:
        return jsonify({
            "error": "RC_LOGS_WEBHOOK not configured",
            "valid": False
        }), 500
    
    # Check if URL format is correct
    checks = {
        "url_set": bool(RC_LOGS_WEBHOOK),
        "starts_with_https": RC_LOGS_WEBHOOK.startswith("https://"),
        "contains_discord": "discord.com" in RC_LOGS_WEBHOOK or "discordapp.com" in RC_LOGS_WEBHOOK,
        "contains_webhooks": "/webhooks/" in RC_LOGS_WEBHOOK,
        "has_token": RC_LOGS_WEBHOOK.count("/") >= 5,
        "length_valid": len(RC_LOGS_WEBHOOK) > 100
    }
    
    all_passed = all(checks.values())
    
    return jsonify({
        "webhook_configured": True,
        "webhook_preview": RC_LOGS_WEBHOOK[:80] + "...",
        "webhook_length": len(RC_LOGS_WEBHOOK),
        "checks": checks,
        "all_checks_passed": all_passed,
        "recommendation": "All checks passed! Try /test-webhook to send a test message." if all_passed else "Some checks failed. Verify your webhook URL is correct."
    }), 200


@app.route("/debug-webhook")
def debug_webhook():
    """Comprehensive webhook debugging"""
    debug_info = {
        "environment_variables": {
            "RC_LOGS_WEBHOOK": "SET" if RC_LOGS_WEBHOOK else "NOT SET",
            "webhook_length": len(RC_LOGS_WEBHOOK) if RC_LOGS_WEBHOOK else 0,
            "DISCORD_BOT_TOKEN": "SET" if BOT_TOKEN else "NOT SET",
            "DISCORD_GUILD_ID": "SET" if GUILD_ID else "NOT SET"
        },
        "webhook_url_analysis": {},
        "test_result": None
    }
    
    if RC_LOGS_WEBHOOK:
        debug_info["webhook_url_analysis"] = {
            "preview": RC_LOGS_WEBHOOK[:80] + "...",
            "starts_with_https": RC_LOGS_WEBHOOK.startswith("https://"),
            "contains_discord": "discord" in RC_LOGS_WEBHOOK.lower(),
            "contains_api": "/api/" in RC_LOGS_WEBHOOK,
            "contains_webhooks": "/webhooks/" in RC_LOGS_WEBHOOK,
            "url_parts_count": RC_LOGS_WEBHOOK.count("/"),
            "total_length": len(RC_LOGS_WEBHOOK)
        }
        
        # Try a simple test
        try:
            response = requests.post(
                RC_LOGS_WEBHOOK,
                json={"content": "Debug test from verification system"},
                timeout=5
            )
            debug_info["test_result"] = {
                "success": response.status_code == 204,
                "status_code": response.status_code,
                "response_text": response.text[:200] if response.text else "Empty (success)"
            }
        except Exception as e:
            debug_info["test_result"] = {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    return jsonify(debug_info), 200
def send_test_log():
    """Send a test verification log to see if webhook works"""
    if not RC_LOGS_WEBHOOK:
        return jsonify({"error": "Webhook not configured"}), 500
    
    # Create fake test data
    test_user = {
        "id": "123456789012345678",
        "username": "TestUser",
        "discriminator": "0",
        "email": "test@example.com",
        "verified": True,
        "avatar": None,
        "banner": None,
        "bio": None,
        "premium_type": 0,
        "public_flags": 0
    }
    
    test_ip_info = {
        "ip": "1.2.3.4",
        "user_agent": "Mozilla/5.0 (Test Browser)",
        "country": "Test Country",
        "country_code": "TC",
        "city": "Test City",
        "region": "Test Region",
        "zip": "12345",
        "isp": "Test ISP",
        "org": "Test Organization",
        "asname": "Test AS",
        "timezone": "UTC",
        "latitude": 0.0,
        "longitude": 0.0,
        "is_mobile": False,
        "is_hosting": False,
        "vpn_detected": False
    }
    
    test_account_age = {
        "created_at": "2024-01-01T00:00:00+00:00",
        "created_at_unix": 1704067200,
        "age_days": 318,
        "age_hours": 7632,
        "age_formatted": "10mo 18d",
        "is_new": False,
        "is_very_new": False,
        "is_suspicious": False,
        "is_fresh": False
    }
    
    test_alt_detection = {
        "risk_score": 25,
        "flags": ["Test flag 1", "Test flag 2", "No custom avatar"],
        "is_likely_alt": False,
        "is_high_risk": False,
        "risk_level": "Low"
    }
    
    test_vpn_check = {
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": False,
        "is_datacenter": False,
        "risk_score": 0,
        "service": "Test Service",
        "blocked": False,
        "details": ["Test detection check passed"]
    }
    
    test_email_analysis = {
        "domain": "example.com",
        "is_disposable": False,
        "is_suspicious": False,
        "provider": "Other",
        "usage_count": 1
    }
    
    test_duplicate_check = {
        "accounts_from_ip": 1,
        "is_shared_ip": False,
        "ip_usage_list": ["123456789012345678"]
    }
    
    test_ua_info = {
        "browser": "Test Browser 1.0",
        "os": "Test OS 10",
        "device": "Test Device",
        "is_mobile": False,
        "is_tablet": False,
        "is_pc": True,
        "is_bot": False
    }
    
    test_guilds_info = {
        "count": 5,
        "names": ["Test Server 1", "Test Server 2", "Test Server 3"],
        "owned": 1
    }
    
    test_connections_info = {
        "count": 2,
        "types": ["steam", "spotify"],
        "verified": 2
    }
    
    # Send the test log
    try:
        success = send_verification_log(
            test_user, test_ip_info, test_account_age, test_alt_detection,
            test_vpn_check, test_email_analysis, test_duplicate_check,
            test_ua_info, test_guilds_info, test_connections_info
        )
        
        if success:
            return jsonify({
                "success": True,
                "message": "Test verification log sent to webhook successfully"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Failed to send test log - check server logs for details"
            }), 500
            
    except Exception as e:
        import traceback
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500


@app.route("/stats")
def stats():
    """Basic statistics endpoint"""
    return jsonify({
        "total_ips": len(ip_usage_tracker),
        "total_verifications": sum(len(v) for v in ip_usage_tracker.values()),
        "unique_users": len(set(uid for uids in ip_usage_tracker.values() for uid in uids)),
        "email_domains_tracked": len(email_domain_tracker),
        "shared_ips": sum(1 for v in ip_usage_tracker.values() if len(set(v)) > 1),
        "verified_users_count": len(verified_users)
    }), 200


@app.route("/pull", methods=["POST"])
def pull_users():
    """Pull all verified users back into the Discord server"""
    # Check authorization
    auth_header = request.headers.get("Authorization")
    
    # Try to get secret from JSON or form data
    secret_param = None
    if request.is_json:
        secret_param = request.json.get("secret")
    elif request.form:
        secret_param = request.form.get("secret")
    
    # Allow both Authorization header and secret parameter
    if auth_header:
        if auth_header != f"Bearer {PULL_SECRET}":
            return jsonify({"error": "Unauthorized", "message": "Invalid authorization token"}), 401
    elif secret_param:
        if secret_param != PULL_SECRET:
            return jsonify({"error": "Unauthorized", "message": "Invalid secret"}), 401
    else:
        return jsonify({"error": "Unauthorized", "message": "Missing authorization. Send Authorization header or secret in body"}), 401
    
    # Check if bot token and guild ID are configured
    if not BOT_TOKEN:
        return jsonify({
            "error": "Configuration error",
            "message": "DISCORD_BOT_TOKEN not configured"
        }), 500
    
    if not GUILD_ID:
        return jsonify({
            "error": "Configuration error",
            "message": "DISCORD_GUILD_ID not configured"
        }), 500
    
    # Check if there are any verified users
    if not verified_users:
        return jsonify({
            "success": True,
            "message": "No verified users to pull",
            "stats": {
                "total": 0,
                "added_to_server": 0,
                "failed": 0,
                "role_assigned": 0,
                "role_failed": 0
            }
        }), 200
    
    print(f"🔄 Starting pull operation for {len(verified_users)} verified users...")
    
    # Pull all verified users
    results = pull_all_verified_users()
    
    # Build response
    response = {
        "success": True,
        "message": f"Pull operation completed",
        "stats": {
            "total": len(verified_users),
            "added_to_server": len(results["success"]),
            "failed": len(results["failed"]),
            "role_assigned": len(results["role_assigned"]),
            "role_failed": len(results["role_failed"])
        },
        "details": {
            "success": results["success"],
            "failed": results["failed"],
            "role_assigned": results["role_assigned"],
            "role_failed": results["role_failed"]
        }
    }
    
    print(f"✅ Pull operation completed: {len(results['success'])} successful, {len(results['failed'])} failed")
    
    # Send webhook notification about pull operation
    if RC_LOGS_WEBHOOK:
        send_pull_notification(response)
    
    return jsonify(response), 200


if __name__ == "__main__":
    print("🚀 Enhanced Discord Verification System Starting...")
    print(f"📊 VPN Blocking: {'Enabled' if BLOCK_VPNS else 'Disabled'}")
    print(f"⚠️  VPN Threshold: {VPN_BLOCK_THRESHOLD}%")
    print(f"🔗 OAuth Scopes: {OAUTH_SCOPE}")
    print(f"🏰 Guild ID: {GUILD_ID if GUILD_ID else '❌ NOT SET'}")
    print(f"🤖 Bot Token: {'✅ SET' if BOT_TOKEN else '❌ NOT SET'}")
    print(f"🪝 Webhook: {'✅ SET' if RC_LOGS_WEBHOOK else '❌ NOT SET'}")
    print(f"🔐 Pull Secret: {'✅ SET' if PULL_SECRET else '❌ NOT SET (Using default - CHANGE THIS!)'}")
    print(f"👥 Member Role ID: {MEMBER_ROLE_ID}")
    print(f"🌐 Redirect URI: {REDIRECT_URI}")
    
    if RC_LOGS_WEBHOOK:
        print(f"🪝 Webhook URL: {RC_LOGS_WEBHOOK[:50]}...")
    
    print("=" * 60)
    
    # Warnings for missing critical config
    if not BOT_TOKEN:
        print("⚠️  WARNING: DISCORD_BOT_TOKEN not set! Auto-join and /pull will NOT work!")
    if not GUILD_ID:
        print("⚠️  WARNING: DISCORD_GUILD_ID not set! Auto-join and /pull will NOT work!")
    if not RC_LOGS_WEBHOOK:
        print("⚠️  WARNING: RC_LOGS_WEBHOOK not set! Logging will NOT work!")
    if PULL_SECRET == "change-this-secret":
        print("⚠️  WARNING: Using default PULL_SECRET! Change this immediately!")
    
    print("=" * 60)
    print(f"✅ Server starting on http://0.0.0.0:8080")
    print(f"🔗 Verification URL: {REDIRECT_URI.replace('/callback', '/verify') if REDIRECT_URI else 'NOT SET'}")
    print(f"\n🧪 Debugging & Test Endpoints:")
    print(f"   - /verify-webhook    - Verify webhook URL format")
    print(f"   - /debug-webhook     - Comprehensive webhook debugging")
    print(f"   - /test-webhook      - Send simple test message")
    print(f"   - /send-test-log     - Send full test verification log")
    print(f"   - /config            - Check configuration")
    print(f"   - /stats             - View statistics")
    print("=" * 60)
    
    # Auto-test webhook on startup if configured
    if RC_LOGS_WEBHOOK:
        print("\n🔍 Auto-testing webhook on startup...")
        try:
            test_response = requests.post(
                RC_LOGS_WEBHOOK,
                json={"content": "✅ Verification system started successfully!"},
                timeout=5
            )
            if test_response.status_code == 204:
                print("✅ Webhook test SUCCESSFUL! Messages will appear in Discord.")
            else:
                print(f"⚠️ Webhook test returned status {test_response.status_code}")
                print(f"   Response: {test_response.text[:200]}")
        except Exception as e:
            print(f"⚠️ Webhook test failed: {e}")
        print("=" * 60)
    
    print("")
    
    app.run(host="0.0.0.0", port=8080, debug=False)
