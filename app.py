import os
import json
import urllib.parse
import hashlib
import re
from datetime import datetime, timezone
from collections import defaultdict

import requests
from flask import Flask, redirect, request, url_for, render_template_string

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
PULL_SECRET = os.getenv("PULL_SECRET", "Kj9mP2nQ8rL5xWvY3zB7cF4dG6hJ1tN0")

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
      <p class="privacy">By verifying, you agree to connect your Discord account.</p>
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
    """Enhanced VPN/Proxy detection"""
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
                result['details'].append(f"ip-api: Datacenter/Hosting")
    except Exception as e:
        result['details'].append(f"ip-api error: {str(e)[:50]}")
    
    if BLOCK_VPNS and result['risk_score'] >= VPN_BLOCK_THRESHOLD:
        result['blocked'] = True
    
    return result


def get_ip_location(ip_address):
    """Get location information from IP"""
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
    """Analyze email domain"""
    if not email or '@' not in email:
        return {'domain': 'Unknown', 'is_disposable': False, 'is_suspicious': False, 'provider': 'Unknown', 'usage_count': 0}
    
    domain = email.split('@')[1].lower()
    
    disposable_domains = {
        'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
        'throwaway.email', 'temp-mail.org', 'getnada.com', 'maildrop.cc'
    }
    
    trusted_providers = {
        'gmail.com': 'Google', 'outlook.com': 'Microsoft', 'hotmail.com': 'Microsoft',
        'yahoo.com': 'Yahoo', 'icloud.com': 'Apple', 'protonmail.com': 'ProtonMail'
    }
    
    is_disposable = domain in disposable_domains
    provider = trusted_providers.get(domain, 'Other')
    
    email_domain_tracker[domain] += 1
    
    return {
        'domain': domain,
        'is_disposable': is_disposable,
        'is_suspicious': is_disposable or len(domain) < 4,
        'provider': provider,
        'usage_count': email_domain_tracker[domain]
    }


def check_duplicate_accounts(user_id, ip_address, email):
    """Check for duplicate accounts"""
    ip_usage_tracker[ip_address].append(user_id)
    accounts_from_ip = len(set(ip_usage_tracker[ip_address]))
    
    return {
        'accounts_from_ip': accounts_from_ip,
        'is_shared_ip': accounts_from_ip > 1,
        'ip_usage_list': list(set(ip_usage_tracker[ip_address]))[:5]
    }


def detect_alt_account(user, account_age, ip_info, email_analysis, duplicate_check, ua_info):
    """Enhanced alt account detection"""
    risk_score = 0
    flags = []
    
    if account_age['is_fresh']:
        risk_score += 50
        flags.append("🚨 Account less than 24 hours old")
    elif account_age['is_suspicious']:
        risk_score += 40
        flags.append("⚠️ Account less than 3 days old")
    elif account_age['is_very_new']:
        risk_score += 25
        flags.append("Account less than 7 days old")
    
    if not user.get('avatar'):
        risk_score += 15
        flags.append("No custom avatar")
    
    if not user.get('verified', False):
        risk_score += 25
        flags.append("Email not verified")
    
    if email_analysis['is_disposable']:
        risk_score += 35
        flags.append("🚨 Disposable email domain")
    
    if duplicate_check['is_shared_ip']:
        risk_score += 25
        flags.append(f"IP used by {duplicate_check['accounts_from_ip']} accounts")
    
    if user.get('premium_type'):
        risk_score = max(0, risk_score - 25)
        flags.append("✅ Has Nitro (reduces risk)")
    
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
    """Add user to the Discord server"""
    if not BOT_TOKEN or not GUILD_ID:
        print("Missing BOT_TOKEN or GUILD_ID")
        return False
    
    url = f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/members/{user_id}"
    headers = {
        "Authorization": f"Bot {BOT_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {"access_token": access_token}
    
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
    """Assign the member role"""
    if not BOT_TOKEN or not GUILD_ID:
        return False
    
    url = f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/members/{user_id}/roles/{MEMBER_ROLE_ID}"
    headers = {"Authorization": f"Bot {BOT_TOKEN}"}
    
    try:
        r = requests.put(url, headers=headers)
        return r.status_code in [200, 204]
    except Exception as e:
        print(f"Error assigning role: {e}")
        return False


def send_verification_log(user, ip_info, account_age, alt_detection, vpn_check, email_analysis, 
                         duplicate_check, ua_info, guilds_info, connections_info):
    """Send comprehensive verification embed to webhook"""
    if not RC_LOGS_WEBHOOK:
        print("❌ No RC_LOGS_WEBHOOK configured - cannot send log")
        return False

    try:
        username = user.get('username', 'Unknown')
        discriminator = user.get('discriminator', '0')
        if discriminator != '0':
            username = f"{username}#{discriminator}"
        
        user_id = user.get("id", "Unknown")
        email = user.get("email", "Not provided")
        
        # Determine embed color
        if vpn_check['blocked'] or alt_detection['is_high_risk']:
            embed_color = 0xff0000
        elif alt_detection['is_likely_alt']:
            embed_color = 0xff8800
        else:
            embed_color = 0x00ff00
        
        risk_emoji = "🔴" if alt_detection['is_high_risk'] else "🟠" if alt_detection['is_likely_alt'] else "🟢"
        alt_status = f"{risk_emoji} {alt_detection['risk_level']} Risk ({alt_detection['risk_score']}%)"
        
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        
        embed = {
            "title": "🔐 Web Verification",
            "description": f"**Risk Assessment:** {alt_status}",
            "color": embed_color,
            "fields": [
                {"name": "Username", "value": f"`{username}`", "inline": True},
                {"name": "User ID", "value": f"`{user_id}`", "inline": True},
                {"name": "Email", "value": email[:50], "inline": True},
                {"name": "Account Age", "value": f"{account_age['age_formatted']}\n<t:{account_age['created_at_unix']}:R>", "inline": True},
                {"name": "Risk Level", "value": alt_status, "inline": True},
                {"name": "IP Address", "value": f"`{ip_info.get('ip', 'Unknown')}`", "inline": True},
                {"name": "Location", "value": f"{ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown')}", "inline": True},
                {"name": "ISP", "value": ip_info.get('isp', 'Unknown')[:50], "inline": True},
                {"name": "Browser", "value": ua_info.get('browser', 'Unknown')[:50], "inline": True},
                {"name": "Servers", "value": f"Total: {guilds_info['count']}", "inline": True},
                {"name": "Risk Flags", "value": '\n'.join(f"• {flag}" for flag in alt_detection['flags'][:5]) if alt_detection['flags'] else "✅ No flags", "inline": False},
            ],
            "footer": {"text": "Enchanted Verification System"},
            "timestamp": now
        }
        
        payload = {"embeds": [embed]}
        
        print(f"📤 Sending webhook to: {RC_LOGS_WEBHOOK[:50]}...")
        response = requests.post(
            RC_LOGS_WEBHOOK, 
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 204:
            print(f"✅ Webhook sent successfully for {username}")
            return True
        else:
            print(f"❌ Webhook failed with status {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to send webhook: {e}")
        import traceback
        traceback.print_exc()
        return False


# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return redirect("/verify")


@app.route("/verify")
def verify_page():
    oauth_url = build_oauth_url()
    return render_template_string(VERIFY_PAGE_HTML, site_name=SITE_NAME, oauth_url=oauth_url)


@app.route("/callback")
def oauth_callback():
    ip_address = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    ua_info = parse_user_agent(user_agent)
    vpn_check = check_vpn_proxy(ip_address)
    
    if vpn_check['blocked']:
        return render_template_string(
            ERROR_PAGE_HTML,
            site_name=SITE_NAME,
            message=f"VPN/Proxy detected. Please disable and try again."
        )
    
    location_data = get_ip_location(ip_address)
    ip_info = {
        'ip': ip_address,
        'user_agent': user_agent,
        'country': location_data['country'],
        'country_code': location_data['country_code'],
        'city': location_data['city'],
        'region': location_data['region'],
        'isp': location_data['isp'],
        'org': location_data['org'],
        'timezone': location_data['timezone'],
        'is_mobile': location_data['is_mobile'],
        'is_hosting': location_data['is_hosting'],
        'vpn_detected': vpn_check['is_vpn'] or vpn_check['is_proxy']
    }
    
    error = request.args.get("error")
    if error:
        return render_template_string(ERROR_PAGE_HTML, site_name=SITE_NAME, message=f"Error: {error}")

    code = request.args.get("code")
    if not code:
        return render_template_string(ERROR_PAGE_HTML, site_name=SITE_NAME, message="Missing OAuth code")

    token_data = exchange_code(code)
    if not token_data:
        return render_template_string(ERROR_PAGE_HTML, site_name=SITE_NAME, message="Failed to exchange code")

    access_token = token_data.get("access_token")
    if not access_token:
        return render_template_string(ERROR_PAGE_HTML, site_name=SITE_NAME, message="No access token received")

    user = get_discord_user(access_token)
    if not user:
        return render_template_string(ERROR_PAGE_HTML, site_name=SITE_NAME, message="Failed to fetch Discord account")

    user_id = user.get("id", "Unknown")
    email = user.get("email", "")
    
    verified_users[user_id] = {
        "access_token": access_token,
        "username": user.get("username"),
        "verified_at": datetime.utcnow().isoformat()
    }
    
    guilds_info = get_discord_guilds(access_token)
    connections_info = get_discord_connections(access_token)
    account_age = calculate_account_age(user_id)
    email_analysis = analyze_email_domain(email)
    duplicate_check = check_duplicate_accounts(user_id, ip_address, email)
    alt_detection = detect_alt_account(user, account_age, ip_info, email_analysis, duplicate_check, ua_info)

    # Send webhook
    webhook_sent = send_verification_log(
        user, ip_info, account_age, alt_detection, vpn_check,
        email_analysis, duplicate_check, ua_info, guilds_info, connections_info
    )
    
    if webhook_sent:
        print("✅ Webhook log sent successfully")
    else:
        print("❌ Webhook log failed to send")

    # Add to guild and assign role
    add_user_to_guild(access_token, user_id)
    assign_member_role(user_id)

    username = user.get('username', 'Unknown')
    discriminator = user.get('discriminator', '0')
    if discriminator != '0':
        username = f"{username}#{discriminator}"

    return render_template_string(SUCCESS_PAGE_HTML, site_name=SITE_NAME, username=username, user_id=user_id)


@app.route("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "ok", "service": "discord-verification"}, 200


@app.route("/config")
def config_check():
    """Debug endpoint to check configuration"""
    return {
        "CLIENT_ID": "SET" if CLIENT_ID else "NOT SET",
        "CLIENT_SECRET": "SET" if CLIENT_SECRET else "NOT SET",
        "REDIRECT_URI": REDIRECT_URI if REDIRECT_URI else "NOT SET",
        "BOT_TOKEN": "SET" if BOT_TOKEN else "NOT SET",
        "GUILD_ID": GUILD_ID if GUILD_ID else "NOT SET",
        "RC_LOGS_WEBHOOK": "SET" if RC_LOGS_WEBHOOK else "NOT SET",
        "WEBHOOK_PREVIEW": RC_LOGS_WEBHOOK[:60] + "..." if RC_LOGS_WEBHOOK else "NOT SET",
        "MEMBER_ROLE_ID": MEMBER_ROLE_ID
    }, 200


@app.route("/test-webhook")
def test_webhook():
    """Test webhook endpoint to verify it's working"""
    if not RC_LOGS_WEBHOOK:
        return {
            "error": "RC_LOGS_WEBHOOK not configured",
            "webhook_set": False
        }, 500
    
    try:
        test_embed = {
            "title": "🧪 Webhook Test",
            "description": "This is a test message to verify the webhook is working correctly.",
            "color": 0x00ff00,
            "fields": [
                {"name": "Status", "value": "✅ Webhook is configured", "inline": True},
                {"name": "Timestamp", "value": datetime.utcnow().isoformat(), "inline": True}
            ],
            "footer": {"text": "Enchanted Verification System"}
        }
        
        payload = {"embeds": [test_embed]}
        print(f"🧪 Testing webhook: {RC_LOGS_WEBHOOK[:50]}...")
        
        response = requests.post(
            RC_LOGS_WEBHOOK,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"Response status: {response.status_code}")
        if response.status_code != 204:
            print(f"Response body: {response.text}")
        
        return {
            "success": response.status_code == 204,
            "status_code": response.status_code,
            "webhook_set": True,
            "webhook_url_preview": RC_LOGS_WEBHOOK[:50] + "...",
            "response_text": response.text if response.status_code != 204 else "Success (204 No Content)"
        }, 200
        
    except Exception as e:
        print(f"❌ Webhook test error: {e}")
        import traceback
        traceback.print_exc()
        return {
            "error": str(e),
            "webhook_set": True,
            "traceback": traceback.format_exc()
        }, 500


@app.route("/stats")
def stats():
    """Basic statistics endpoint"""
    return {
        "total_ips": len(ip_usage_tracker),
        "total_verifications": sum(len(v) for v in ip_usage_tracker.values()),
        "unique_users": len(set(uid for uids in ip_usage_tracker.values() for uid in uids)),
        "email_domains_tracked": len(email_domain_tracker),
        "verified_users_count": len(verified_users)
    }, 200


@app.route("/pull", methods=["POST"])
def pull_users():
    """Pull all verified users back into the Discord server"""
    auth_header = request.headers.get("Authorization")
    secret_param = request.json.get("secret") if request.is_json else request.form.get("secret")
    
    if auth_header:
        if auth_header != f"Bearer {PULL_SECRET}":
            return {"error": "Unauthorized"}, 401
    elif secret_param:
        if secret_param != PULL_SECRET:
            return {"error": "Unauthorized"}, 401
    else:
        return {"error": "Unauthorized"}, 401
    
    if not BOT_TOKEN or not GUILD_ID:
        return {"error": "Configuration error"}, 500
    
    if not verified_users:
        return {
            "success": True,
            "message": "No verified users to pull",
            "stats": {"total": 0, "success": 0, "failed": 0}
        }, 200
    
    success_count = 0
    failed_count = 0
    
    for user_id, user_data in verified_users.items():
        access_token = user_data.get("access_token")
        if access_token and add_user_to_guild(access_token, user_id):
            assign_member_role(user_id)
            success_count += 1
        else:
            failed_count += 1
    
    return {
        "success": True,
        "stats": {
            "total": len(verified_users),
            "success": success_count,
            "failed": failed_count
        }
    }, 200


if __name__ == "__main__":
    print("🚀 Enhanced Discord Verification System Starting...")
    print(f"📊 VPN Blocking: {'Enabled' if BLOCK_VPNS else 'Disabled'}")
    print(f"🏰 Guild ID: {GUILD_ID if GUILD_ID else '❌ NOT SET'}")
    print(f"🤖 Bot Token: {'✅ SET' if BOT_TOKEN else '❌ NOT SET'}")
    print(f"🪝 Webhook: {'✅ SET' if RC_LOGS_WEBHOOK else '❌ NOT SET'}")
    
    if RC_LOGS_WEBHOOK:
        print(f"🪝 Webhook URL: {RC_LOGS_WEBHOOK[:50]}...")
    
    if not BOT_TOKEN:
        print("⚠️  WARNING: DISCORD_BOT_TOKEN not set!")
    if not GUILD_ID:
        print("⚠️  WARNING: DISCORD_GUILD_ID not set!")
    if not RC_LOGS_WEBHOOK:
        print("⚠️  WARNING: RC_LOGS_WEBHOOK not set!")
    
    print("=" * 60)
    print(f"✅ Server starting on http://0.0.0.0:8080")
    print(f"🧪 Test webhook at: http://your-domain.com/test-webhook")
    print("=" * 60)
    
    app.run(host="0.0.0.0", port=8080, debug=False)
