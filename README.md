# 🤖 Self-Modifying Discord Bot

A production-ready Discord bot built with the latest discord.js (v14.25.1) that can **generate its own commands dynamically** and **hot-reload** them without restarting. Optimized for VPS deployment with pm2.

## ✨ Features

### Core Capabilities
- **Self-Modifying Code**: Generate new command files at runtime using `/gwencode`
- **Hot-Reloading**: Commands are automatically loaded from disk with cache clearing
- **Owner-Only Protection**: Critical commands restricted to bot owner
- **Safety First**: Faulty generated code is automatically deleted, preventing crashes

### Built-in Commands
| Command | Description | Owner Only |
|---------|-------------|------------|
| `/ping` | Check bot latency | ❌ |
| `/help` | Show help menu | ❌ |
| `/gwencode` | Generate new commands dynamically | ✅ |

### Technical Features
- Collection-based command handler
- Dynamic ES module imports with cache busting
- REST API integration for in-place command updates
- Graceful error handling and shutdown
- Welcome/Goodbye messages for members

---

## 📋 Prerequisites

- **Node.js** v18.0.0 or higher
- **Discord Bot Token** (from Discord Developer Portal)
- **Linux VPS** (recommended for 24/7 hosting)

---

## 🚀 Setup Instructions

### Step 1: Create Discord Application

1. Visit [Discord Developer Portal](https://discord.com/developers/applications)
2. Click **"New Application"** and give it a name
3. Go to the **"Bot"** section
4. Click **"Reset Token"** and copy your bot token
5. Enable these **Privileged Gateway Intents**:
   - ✅ Server Members Intent
   - ✅ Message Content Intent
6. Save changes

### Step 2: Invite Bot to Server

1. Go to **"OAuth2" → "URL Generator"**
2. Select scopes: `bot`, `applications.commands`
3. Select permissions: `Administrator` (or specific permissions)
4. Copy the generated URL and open it in browser
5. Select your server and authorize

### Step 3: Get Required IDs

Enable **Developer Mode** in Discord:
- User Settings → Advanced → Developer Mode

Then right-click and copy IDs for:
- Your user (for `OWNER_ID`)
- Your server (for `GUILD_ID`)
- The bot (for `CLIENT_ID`)

### Step 4: Configure Environment

```bash
cd /path/to/bot
cp .env.example .env
nano .env
```

Fill in your values:
```env
DISCORD_TOKEN=your_bot_token_here
CLIENT_ID=your_bot_client_id_here
GUILD_ID=your_server_id_here
OWNER_ID=your_discord_user_id_here
```

### Step 5: Install Dependencies

```bash
npm install
```

### Step 6: Deploy Commands

```bash
npm run deploy
```

### Step 7: Start the Bot

```bash
npm start
```

---

## 🖥️ VPS Deployment with PM2

### Install PM2

```bash
npm install -g pm2
```

### Start Bot with PM2

```bash
pm2 start src/index.js --name "discord-bot"
```

### Additional PM2 Commands

```bash
# View running processes
pm2 status

# View logs
pm2 logs discord-bot

# Restart bot
pm2 restart discord-bot

# Stop bot
pm2 stop discord-bot

# Delete from PM2
pm2 delete discord-bot

# Setup PM2 to start on system boot
pm2 startup
pm2 save
```

### Recommended PM2 Ecosystem Config

Create `ecosystem.config.js`:

```javascript
module.exports = {
  apps: [{
    name: 'discord-bot',
    script: './src/index.js',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '500M',
    env: {
      NODE_ENV: 'production'
    }
  }]
};
```

Then run:
```bash
pm2 start ecosystem.config.js
```

---

## 💡 Using the Self-Modifying Feature

### Generate a New Command

Use the `/gwencode` command (owner only):

```
/gwencode prompt:"create a command /ping that says pong"
```

Or with custom name:
```
/gwencode prompt:"make a dice rolling command" name:"roll"
```

### How It Works

1. Bot receives your prompt
2. Analyzes keywords to determine command type
3. Generates valid JavaScript code
4. Writes file to `./commands/` directory
5. Reports success with file location

### Example Generated Commands

**Ping Command:**
```
/gwencode prompt:"create a command /ping that says pong"
```

**Dice Roll Command:**
```
/gwencode prompt:"create a command that rolls a dice with customizable sides"
```

**Server Info Command:**
```
/gwencode prompt:"create a command that shows server information"
```

---

## 📁 Project Structure

```
/workspace/
├── src/
│   ├── commands/          # Command files (auto-populated)
│   │   ├── ping.js
│   │   ├── help.js
│   │   └── gwencode.js
│   ├── utils/
│   │   ├── CommandHandler.js   # Hot-reload capable handler
│   │   └── CodeGenerator.js    # Command generation logic
│   ├── index.js                # Main bot entry point
│   └── deploy-commands.js      # Command registration script
├── .env                        # Environment variables (gitignored)
├── .env.example                # Template for .env
├── package.json
├── README.md
└── ecosystem.config.js         # PM2 configuration (optional)
```

---

## 🔒 Security Features

### Owner-Only Commands
The `/gwencode` command checks against `OWNER_ID` before execution.

### Safe Code Generation
- Generated code is validated before writing
- Syntax errors trigger automatic file deletion
- Errors are caught and reported, never crash the bot

### Environment Validation
Bot refuses to start if required environment variables are missing.

---

## 🛠️ Troubleshooting

### Bot doesn't respond to commands
1. Ensure commands are deployed: `npm run deploy`
2. Check bot has proper permissions
3. Verify `GUILD_ID` is correct

### Commands not appearing
1. Wait up to 1 hour for global commands (guild commands appear instantly)
2. Try kicking and re-inviting the bot
3. Re-run `npm run deploy`

### "Missing Intents" error
Enable required intents in Discord Developer Portal:
- Server Members Intent
- Message Content Intent

### Hot-reload not working
1. Ensure file was written successfully
2. Check console for load errors
3. Restart bot if needed: `pm2 restart discord-bot`

---

## 📦 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| discord.js | ^14.25.1 | Main Discord API wrapper |
| @discordjs/core | ^2.4.0 | REST API and utilities |
| @discordjs/voice | ^0.19.1 | Voice support (ready for expansion) |
| dotenv | ^16.4.5 | Environment variable management |

---

## 🎯 Future Enhancements

- [ ] Integrate Qwen API for AI-powered command generation
- [ ] Add command categories and help pagination
- [ ] Implement database for persistent settings
- [ ] Add moderation commands suite
- [ ] Web dashboard for bot management
- [ ] Plugin system for community extensions

---

## 📄 License

MIT License - Feel free to use and modify!

---

## 🤝 Support

For issues or questions:
1. Check this README
2. Review error logs with `pm2 logs`
3. Ensure all environment variables are set correctly

**Happy coding! 🚀**
