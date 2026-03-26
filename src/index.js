import { Client, Collection, Events, GatewayIntentBits, EmbedBuilder } from 'discord.js';
import { REST } from '@discordjs/rest';
import { Routes } from 'discord-api-types/v10';
import dotenv from 'dotenv';
import { CommandHandler } from './utils/CommandHandler.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Load environment variables
dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));

// Validate required environment variables
const requiredEnv = ['DISCORD_TOKEN', 'CLIENT_ID', 'GUILD_ID', 'OWNER_ID'];
for (const env of requiredEnv) {
    if (!process.env[env]) {
        console.error(`❌ Missing required environment variable: ${env}`);
        console.error('Please copy .env.example to .env and fill in all values.');
        process.exit(1);
    }
}

// Create client with necessary intents
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent
    ]
});

// Initialize command handler
const commandHandler = new CommandHandler(client);
client.commands = commandHandler.commands;

// REST instance for command updates
const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);

/**
 * Register commands with Discord
 */
async function registerCommands() {
    try {
        console.log('🔄 Started refreshing application (/) commands.');
        
        const commands = commandHandler.getAllCommands();
        
        // Register commands for the specific guild
        await rest.put(
            Routes.applicationGuildCommands(process.env.CLIENT_ID, process.env.GUILD_ID),
            { body: commands }
        );
        
        console.log('✅ Successfully reloaded application (/) commands.');
    } catch (error) {
        console.error('❌ Failed to register commands:', error);
    }
}

/**
 * Load all commands from the commands directory
 */
async function loadAllCommands() {
    console.log('📂 Loading commands...');
    const count = await commandHandler.loadCommands();
    console.log(`📦 Loaded ${count} commands.`);
    return count;
}

/**
 * Handle command execution with safety checks
 */
async function handleCommand(interaction) {
    if (!interaction.isChatInputCommand()) return;

    const command = client.commands.get(interaction.commandName);

    if (!command) {
        console.error(`No command matching ${interaction.commandName} was found.`);
        return;
    }

    try {
        await command.execute(interaction);
    } catch (error) {
        console.error(`Error executing ${interaction.commandName}:`, error);
        
        const errorMessage = {
            content: 'There was an error while executing this command!',
            ephemeral: true
        };
        
        if (interaction.replied || interaction.deferred) {
            await interaction.followUp(errorMessage);
        } else {
            await interaction.reply(errorMessage);
        }
    }
}

/**
 * Hot-reload a specific command file
 */
async function hotReloadCommand(commandName) {
    try {
        const success = await commandHandler.reloadCommand(commandName);
        if (success) {
            // Re-register commands with Discord
            await registerCommands();
            return true;
        }
        return false;
    } catch (error) {
        console.error(`Failed to hot-reload command ${commandName}:`, error);
        return false;
    }
}

// Event: Client ready
client.once(Events.ClientReady, async (readyClient) => {
    console.log('');
    console.log('╔════════════════════════════════════════╗');
    console.log('║     🤖 Self-Modifying Bot Ready!       ║');
    console.log('╚════════════════════════════════════════╝');
    console.log('');
    console.log(`✅ Logged in as: ${readyClient.user.tag}`);
    console.log(`🆔 Client ID: ${readyClient.user.id}`);
    console.log(`🏠 Guild ID: ${process.env.GUILD_ID}`);
    console.log(`👑 Owner ID: ${process.env.OWNER_ID}`);
    console.log('');
    
    // Load commands
    await loadAllCommands();
    
    // Register commands with Discord
    await registerCommands();
    
    console.log('');
    console.log('🎉 Bot is ready! Use /help to see available commands.');
    console.log('💡 Use /gwencode to generate new commands dynamically!');
    console.log('');
    
    // Set bot status
    readyClient.user.setPresence({
        activities: [{ name: '/help | Self-Modifying Bot', type: 2 }], // Type 2 = Watching
        status: 'online'
    });
});

// Event: Interaction handler
client.on(Events.InteractionCreate, async (interaction) => {
    // Handle slash commands
    if (interaction.isChatInputCommand()) {
        await handleCommand(interaction);
    }
    
    // Handle button interactions (if any)
    if (interaction.isButton()) {
        console.log(`Button clicked: ${interaction.customId}`);
    }
    
    // Handle select menu interactions (if any)
    if (interaction.isStringSelectMenu()) {
        console.log(`Select menu used: ${interaction.customId}`);
    }
});

// Event: Guild member join (optional welcome feature)
client.on(Events.GuildMemberAdd, async (member) => {
    const welcomeChannel = member.guild.systemChannel;
    if (welcomeChannel) {
        const embed = new EmbedBuilder()
            .setColor(0x00FF00)
            .setTitle('👋 Welcome!')
            .setDescription(`Welcome ${member.user.tag} to **${member.guild.name}**!`)
            .setThumbnail(member.user.displayAvatarURL())
            .setTimestamp();
        
        await welcomeChannel.send({ embeds: [embed] }).catch(console.error);
    }
});

// Event: Guild member leave (optional goodbye feature)
client.on(Events.GuildMemberRemove, async (member) => {
    const welcomeChannel = member.guild.systemChannel;
    if (welcomeChannel) {
        const embed = new EmbedBuilder()
            .setColor(0xFF0000)
            .setTitle('👋 Goodbye')
            .setDescription(`${member.user.tag} has left **${member.guild.name}**.`)
            .setTimestamp();
        
        await welcomeChannel.send({ embeds: [embed] }).catch(console.error);
    }
});

// Error handling
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Received SIGINT. Shutting down gracefully...');
    client.destroy();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n🛑 Received SIGTERM. Shutting down gracefully...');
    client.destroy();
    process.exit(0);
});

// Login to Discord
console.log('🔑 Attempting to login...');
client.login(process.env.DISCORD_TOKEN);

// Export for testing and external access
export { client, commandHandler, hotReloadCommand, registerCommands };
