import os
import json
import urllib.parse
from datetime import datetime

import requests
from flask import Flask, redirect, request, url_for, render_template_string

app = Flask(__name__)

# ---------------- CONFIG ----------------
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
RC_LOGS_WEBHOOK = os.getenv("RC_LOGS_WEBHOOK")

OAUTH_SCOPE = "identify"
DISCORD_API_BASE = "https://discord.com/api"
SITE_NAME = "Enchanted Verification"

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
      <p class="privacy">By verifying, you agree to connect your Discord account. We collect your username, ID, IP address, and browser information for security purposes.</p>
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

def get_client_ip():
    """Get the user's IP address, accounting for proxies"""
    # Check for common proxy headers
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, take the first one
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip


def get_ip_location(ip_address):
    """Get location information from IP address using ip-api.com (free, no key required)"""
    try:
        # Using ip-api.com free API (no key required, 45 requests/minute limit)
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
                    'isp': data.get('isp', 'Unknown')
                }
    except Exception as e:
        print(f"Failed to get IP location: {e}")
    
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'region': 'Unknown',
        'latitude': None,
        'longitude': None,
        'isp': 'Unknown'
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


def send_verification_log(user: dict, ip_info: dict):
    """
    Sends an embed to your RC logs webhook with user info and IP data
    """
    if not RC_LOGS_WEBHOOK:
        print("No RC_LOGS_WEBHOOK configured")
        return

    username = f"{user.get('username', 'Unknown')}#{user.get('discriminator', '0')}"
    user_id = user.get("id", "Unknown")
    avatar_hash = user.get("avatar")

    avatar_url = None
    if avatar_hash and user_id:
        avatar_url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png?size=256"

    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    embed = {
        "title": "New Web Verification",
        "description": "A user has successfully verified via the Enchanted website.",
        "color": 0x6f3bbd,
        "fields": [
            {"name": "User", "value": f"{username}", "inline": True},
            {"name": "User ID", "value": f"`{user_id}`", "inline": True},
            {"name": "IP Address", "value": f"`{ip_info['ip']}`", "inline": False},
            {"name": "Location", "value": f"{ip_info['city']}, {ip_info['region']}, {ip_info['country']}", "inline": True},
            {"name": "ISP", "value": ip_info['isp'], "inline": True},
            {"name": "User Agent", "value": f"```{ip_info['user_agent'][:100]}```", "inline": False},
            {"name": "Verified at (UTC)", "value": now, "inline": False},
        ],
        "footer": {"text": "Enchanted • Web Verification"},
    }

    payload = {"embeds": [embed]}
    if avatar_url:
        payload["embeds"][0]["thumbnail"] = {"url": avatar_url}

    try:
        requests.post(RC_LOGS_WEBHOOK, data=json.dumps(payload), headers={"Content-Type": "application/json"})
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
    # Collect IP and browser information
    ip_address = get_client_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    location_data = get_ip_location(ip_address)
    
    ip_info = {
        'ip': ip_address,
        'user_agent': user_agent,
        'country': location_data['country'],
        'city': location_data['city'],
        'region': location_data['region'],
        'isp': location_data['isp']
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

    # Send verification log with IP info
    send_verification_log(user, ip_info)

    username = f"{user.get('username', 'Unknown')}#{user.get('discriminator', '0')}"
    user_id = user.get("id", "Unknown")

    return render_template_string(
        SUCCESS_PAGE_HTML,
        site_name=SITE_NAME,
        username=username,
        user_id=user_id
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
