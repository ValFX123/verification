import { REST, Routes } from '@discordjs/core';
import dotenv from 'dotenv';
import { CommandHandler } from './utils/CommandHandler.js';
import { Client } from 'discord.js';

dotenv.config();

// Validate required environment variables
const requiredEnv = ['DISCORD_TOKEN', 'CLIENT_ID', 'GUILD_ID'];
for (const env of requiredEnv) {
    if (!process.env[env]) {
        console.error(`❌ Missing required environment variable: ${env}`);
        process.exit(1);
    }
}

async function deployCommands() {
    // Create a minimal client to use the command handler
    const client = new Client({ intents: [] });
    const commandHandler = new CommandHandler(client);
    
    console.log('📂 Loading commands...');
    await commandHandler.loadCommands();
    
    const commands = commandHandler.getAllCommands();
    
    if (commands.length === 0) {
        console.log('⚠️  No commands found to deploy.');
        return;
    }
    
    console.log(`📦 Found ${commands.length} commands to deploy.`);
    
    // Create REST instance
    const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);
    
    try {
        console.log('🔄 Started refreshing application (/) commands.');
        
        // Deploy commands to the specific guild
        await rest.put(
            Routes.applicationGuildCommands(process.env.CLIENT_ID, process.env.GUILD_ID),
            { body: commands }
        );
        
        console.log('✅ Successfully deployed application (/) commands.');
        console.log('💡 Commands may take a few moments to appear in Discord.');
    } catch (error) {
        console.error('❌ Failed to deploy commands:', error);
        process.exit(1);
    }
}

deployCommands();
