import os
import json
import urllib.parse
import hashlib
import re
from datetime import datetime, timezone
from collections import defaultdict

import requests
from flask import Flask, redirect, request, url_for, render_template_string
from user_agents import parse

app = Flask(__name__)

# ---------------- CONFIG ----------------
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
RC_LOGS_WEBHOOK = os.getenv("RC_LOGS_WEBHOOK")
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
GUILD_ID = os.getenv("DISCORD_GUILD_ID")
MEMBER_ROLE_ID = "1437971141925929139"
PULL_SECRET = os.getenv("PULL_SECRET", "change-this-secret")  # Secret key for /pull endpoint

OAUTH_SCOPE = "identify email guilds guilds.members.read connections guilds.join"  # Added guilds.join
DISCORD_API_BASE = "https://discord.com/api"
SITE_NAME = "Enchanted Verification"

# VPN/Proxy detection threshold (0-100, higher = stricter)
VPN_BLOCK_THRESHOLD = 75
BLOCK_VPNS = True

# In-memory tracking (use Redis/database in production)
ip_usage_tracker = defaultdict(list)
email_domain_tracker = defaultdict(int)
fingerprint_tracker = defaultdict(list)

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
    <script>
      function getFingerprint() {
        const data = {
          screen: screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          language: navigator.language,
          platform: navigator.platform,
          hardwareConcurrency: navigator.hardwareConcurrency || 0,
          deviceMemory: navigator.deviceMemory || 0,
          touchSupport: 'ontouchstart' in window,
          plugins: Array.from(navigator.plugins || []).map(p => p.name).join(','),
          canvas: getCanvasFingerprint(),
          webgl: getWebGLFingerprint(),
          fonts: detectFonts()
        };
        return btoa(JSON.stringify(data));
      }
      
      function getCanvasFingerprint() {
        try {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          ctx.textBaseline = 'top';
          ctx.font = '14px Arial';
          ctx.fillText('fingerprint', 2, 2);
          return canvas.toDataURL().slice(-50);
        } catch(e) { return 'error'; }
      }
      
      function getWebGLFingerprint() {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (!gl) return 'unsupported';
          const info = gl.getExtension('WEBGL_debug_renderer_info');
          return info ? gl.getParameter(info.UNMASKED_RENDERER_WEBGL) : 'unavailable';
        } catch(e) { return 'error'; }
      }
      
      function detectFonts() {
        const fonts = ['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia', 'Comic Sans MS'];
        const detected = [];
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testString = 'mmmmmmmmmmlli';
        const testSize = '72px';
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        for (const font of fonts) {
          ctx.font = testSize + ' ' + font + ', monospace';
          const width = ctx.measureText(testString).width;
          if (width > 0) detected.push(font);
        }
        return detected.join(',');
      }
      
      window.addEventListener('load', () => {
        sessionStorage.setItem('fp', getFingerprint());
      });
    </script>
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

def get_client_ip():
    """Get the user's IP address, accounting for proxies"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip


def get_browser_fingerprint():
    """Extract browser fingerprint from sessionStorage if available"""
    return request.cookies.get('fp', 'Not captured')


def parse_user_agent(ua_string):
    """Parse user agent into detailed components"""
    try:
        user_agent = parse(ua_string)
        return {
            'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
            'os': f"{user_agent.os.family} {user_agent.os.version_string}",
            'device': user_agent.device.family,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'is_bot': user_agent.is_bot
        }
    except:
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
    
    # Check IP against known VPN ranges (simplified example)
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
    # Add known VPN provider IP ranges here
    # This is a simplified example
    vpn_ranges = [
        '185.220.',  # TOR
        '185.100.',  # Common VPN
    ]
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
        return {'domain': 'Unknown', 'is_disposable': False, 'is_suspicious': False, 'provider': 'Unknown'}
    
    domain = email.split('@')[1].lower()
    
    # Common disposable email domains
    disposable_domains = {
        'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
        'throwaway.email', 'temp-mail.org', 'getnada.com', 'maildrop.cc'
    }
    
    # Trusted email providers
    trusted_providers = {
        'gmail.com': 'Google', 'outlook.com': 'Microsoft', 'hotmail.com': 'Microsoft',
        'yahoo.com': 'Yahoo', 'icloud.com': 'Apple', 'protonmail.com': 'ProtonMail',
        'aol.com': 'AOL', 'mail.com': 'Mail.com'
    }
    
    is_disposable = domain in disposable_domains
    provider = trusted_providers.get(domain, 'Other')
    
    # Check for suspicious patterns
    is_suspicious = (
        is_disposable or
        len(domain) < 4 or
        domain.count('.') > 2 or
        any(char.isdigit() for char in domain.split('.')[0])
    )
    
    # Track domain usage
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
        'ip_usage_list': list(set(ip_usage_tracker[ip_address]))[:5]  # First 5
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
    if not user.get('bio'):
        risk_score += 5
        flags.append("No bio")
    
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
                'names': [g.get('name', 'Unknown')[:30] for g in guilds[:10]],  # First 10
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


def send_verification_log(user, ip_info, account_age, alt_detection, vpn_check, email_analysis, 
                         duplicate_check, ua_info, guilds_info, connections_info):
    """Send comprehensive verification embed to webhook"""
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
    
    premium_type = user.get("premium_type")
    nitro_status = {0: "None", 1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}.get(premium_type, "None")
    
    has_banner = "✅ Yes" if user.get("banner") else "❌ No"
    has_avatar = "✅ Yes" if avatar_hash else "❌ No (Default)"
    has_bio = "✅ Yes" if user.get("bio") else "❌ No"
    
    # Decode badges
    public_flags = user.get('public_flags', 0)
    badges = decode_public_flags(public_flags)
    badge_str = ', '.join(badges[:3]) if badges != ['None'] else 'None'

    avatar_url = None
    if avatar_hash and user_id:
        avatar_url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png?size=256"

    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    user_agent_short = ip_info['user_agent'][:150] if ip_info['user_agent'] else 'Unknown'

    # Determine embed color
    if vpn_check['blocked'] or alt_detection['is_high_risk']:
        embed_color = 0xff0000  # Red
    elif alt_detection['is_likely_alt']:
        embed_color = 0xff8800  # Orange
    elif alt_detection['risk_score'] >= 40:
        embed_color = 0xffcc00  # Yellow
    else:
        embed_color = 0x00ff00  # Green

    # VPN status
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
    risk_emoji = "🔴" if alt_detection['is_high_risk'] else "🟠" if alt_detection['is_likely_alt'] else "🟡" if alt_detection['risk_score'] >= 40 else "🟢"
    alt_status = f"{risk_emoji} {alt_detection['risk_level']} Risk ({alt_detection['risk_score']}%)"

    # Build comprehensive embed
    embed = {
        "title": "🔐 Enhanced Web Verification",
        "description": f"**Risk Assessment:** {alt_status}\n**Detection Details:** {len(alt_detection['flags'])} flags raised",
        "color": embed_color,
        "fields": [
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**👤 Account Information**", "inline": False},
            {"name": "Username", "value": f"`{username}`", "inline": True},
            {"name": "User ID", "value": f"`{user_id}`", "inline": True},
            {"name": "Badges", "value": badge_str[:100], "inline": True},
            
            {"name": "Email", "value": f"{email}\n{email_verified}", "inline": True},
            {"name": "Email Domain", "value": f"{email_analysis['provider']}\n{'🚨 Disposable' if email_analysis['is_disposable'] else '✅ Standard'}", "inline": True},
            {"name": "Domain Usage", "value": f"Used {email_analysis['usage_count']} time(s)", "inline": True},
            
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**📊 Account Statistics**", "inline": False},
            {"name": "Account Age", "value": f"{account_age['age_formatted']}\nCreated: <t:{account_age['created_at_unix']}:R>\nExact: <t:{account_age['created_at_unix']}:F>", "inline": True},
            {"name": "Nitro Status", "value": nitro_status, "inline": True},
            {"name": "Customization", "value": f"Avatar: {has_avatar}\nBanner: {has_banner}\nBio: {has_bio}", "inline": True},
            
            {"name": "Servers", "value": f"Total: {guilds_info['count']}\nOwned: {guilds_info['owned']}", "inline": True},
            {"name": "Connections", "value": f"Total: {connections_info['count']}\nVerified: {connections_info['verified']}\nTypes: {', '.join(connections_info['types'][:3])}" if connections_info['types'] else f"Total: {connections_info['count']}\nNone connected", "inline": True},
            {"name": "Public Flags", "value": f"Raw: `{public_flags}`\nBadges: {len(badges) if badges != ['None'] else 0}", "inline": True},
            
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**🚨 Security Analysis**", "inline": False},
            {"name": "Risk Level", "value": alt_status, "inline": True},
            {"name": "Risk Flags", "value": '\n'.join(f"• {flag}" for flag in alt_detection['flags'][:8]) if alt_detection['flags'] else "✅ No flags", "inline": False},
            
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**🌐 Network Security**", "inline": False},
            {"name": "VPN/Proxy Status", "value": f"{vpn_status}\nRisk: {vpn_check['risk_score']}%\nChecks: {len(vpn_check['details'])}", "inline": True},
            {"name": "Detection Details", "value": '\n'.join(f"• {d}" for d in vpn_check['details'][:4]) if vpn_check['details'] else "No detections", "inline": True},
            {"name": "IP Reuse", "value": f"Accounts: {duplicate_check['accounts_from_ip']}\n{'⚠️ Shared IP' if duplicate_check['is_shared_ip'] else '✅ Unique IP'}", "inline": True},
            
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**📍 Connection Details**", "inline": False},
            {"name": "IP Address", "value": f"`{ip_info.get('ip', 'Unknown')}`", "inline": True},
            {"name": "Location", "value": f"🌍 {ip_info.get('city', 'Unknown')}, {ip_info.get('region', 'Unknown')}\n🏳️ {ip_info.get('country', 'Unknown')} ({ip_info.get('country_code', '??')})\n🕐 {ip_info.get('timezone', 'Unknown')}", "inline": True},
            {"name": "Network Info", "value": f"ISP: {ip_info.get('isp', 'Unknown')[:40]}\nOrg: {ip_info.get('org', 'Unknown')[:40]}\nASN: {ip_info.get('asname', 'Unknown')[:40]}", "inline": True},
            
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**💻 Device Information**", "inline": False},
            {"name": "Browser", "value": ua_info.get('browser', 'Unknown')[:50], "inline": True},
            {"name": "Operating System", "value": ua_info.get('os', 'Unknown')[:50], "inline": True},
            {"name": "Device Type", "value": f"{ua_info.get('device', 'Unknown')}\n{'📱 Mobile' if ua_info.get('is_mobile') else '💻 Desktop' if ua_info.get('is_pc') else '📱 Tablet' if ua_info.get('is_tablet') else '❓ Unknown'}", "inline": True},
            
            {"name": "User Agent", "value": f"`{user_agent_short}`", "inline": False},
            {"name": "Connection Type", "value": f"{'📱 Mobile Network' if ip_info.get('is_mobile') else '🏢 Datacenter' if ip_info.get('is_hosting') else '🏠 Residential'}", "inline": True},
            {"name": "Coordinates", "value": f"Lat: {ip_info.get('latitude', 'N/A')}\nLon: {ip_info.get('longitude', 'N/A')}" if ip_info.get('latitude') else "Not available", "inline": True},
            
            {"name": "━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**⏰ Timestamps**", "inline": False},
            {"name": "Verification Time (UTC)", "value": now, "inline": True},
            {"name": "Account Created", "value": f"<t:{account_age['created_at_unix']}:R>", "inline": True},
            {"name": "Age in Hours", "value": f"{account_age['age_hours']} hours", "inline": True},
        ],
        "footer": {
            "text": f"Enchanted Enhanced Verification • Service: {vpn_check['service']} • Flags: {len(alt_detection['flags'])}"
        },
        "timestamp": now
    }

    # Add server list if available
    if guilds_info['names']:
        server_list = '\n'.join(f"• {name}" for name in guilds_info['names'][:8])
        embed["fields"].insert(10, {
            "name": "Top Servers", 
            "value": server_list, 
            "inline": False
        })

    payload = {"embeds": [embed]}
    if avatar_url:
        payload["embeds"][0]["thumbnail"] = {"url": avatar_url}

    try:
        response = requests.post(
            RC_LOGS_WEBHOOK, 
            data=json.dumps(payload), 
            headers={"Content-Type": "application/json"}
        )
        if response.status_code != 204:
            print(f"Webhook failed with status {response.status_code}: {response.text}")
        else:
            print(f"✅ Verification logged for {username} (Risk: {alt_detection['risk_score']}%)")
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
    send_verification_log(
        user, ip_info, account_age, alt_detection, vpn_check,
        email_analysis, duplicate_check, ua_info, guilds_info, connections_info
    )

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
    return {"status": "ok", "service": "discord-verification"}, 200


@app.route("/stats")
def stats():
    """Basic statistics endpoint (add authentication in production!)"""
    return {
        "total_ips": len(ip_usage_tracker),
        "total_verifications": sum(len(v) for v in ip_usage_tracker.values()),
        "unique_users": len(set(uid for uids in ip_usage_tracker.values() for uid in uids)),
        "email_domains_tracked": len(email_domain_tracker),
        "shared_ips": sum(1 for v in ip_usage_tracker.values() if len(set(v)) > 1)
    }, 200


if __name__ == "__main__":
    print("🚀 Enhanced Discord Verification System Starting...")
    print(f"📊 VPN Blocking: {'Enabled' if BLOCK_VPNS else 'Disabled'}")
    print(f"⚠️  VPN Threshold: {VPN_BLOCK_THRESHOLD}%")
    print(f"🔗 OAuth Scopes: {OAUTH_SCOPE}")
    app.run(host="0.0.0.0", port=8080, debug=False)
