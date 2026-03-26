import { SlashCommandBuilder, EmbedBuilder } from 'discord.js';
import { CodeGenerator } from '../utils/CodeGenerator.js';

export default {
    data: new SlashCommandBuilder()
        .setName('gwencode')
        .setDescription('Generate a new command using AI (Owner only)')
        .addStringOption(option =>
            option.setName('prompt')
                .setDescription('Describe the command you want to create (e.g., "create a command /ping that says pong")')
                .setRequired(true)
        )
        .addStringOption(option =>
            option.setName('name')
                .setDescription('Optional: Custom name for the command file')
                .setRequired(false)
        ),
    
    async execute(interaction) {
        // Owner-only check
        const ownerId = process.env.OWNER_ID;
        if (!ownerId || interaction.user.id !== ownerId) {
            const errorEmbed = new EmbedBuilder()
                .setColor(0xFF0000)
                .setTitle('❌ Access Denied')
                .setDescription('This command can only be used by the bot owner.')
                .setTimestamp();
            
            await interaction.reply({ embeds: [errorEmbed], ephemeral: true });
            return;
        }

        const prompt = interaction.options.getString('prompt');
        const customName = interaction.options.getString('name');

        // Defer reply for long-running operation
        await interaction.deferReply({ ephemeral: true });

        try {
            // Extract command name from prompt or use custom name
            let commandName = customName;
            if (!commandName) {
                // Try to extract from prompt like "/commandname"
                const match = prompt.match(/\/([a-z0-9_-]+)/i);
                if (match) {
                    commandName = match[1].toLowerCase();
                } else {
                    // Generate a simple name from first word
                    commandName = prompt.split(' ')[0].toLowerCase().replace(/[^a-z0-9_-]/g, '');
                }
            }

            // Initialize code generator
            const generator = new CodeGenerator();

            // Generate the command file
            const result = await generator.generateCommand(prompt, commandName);

            // Attempt to hot-reload commands
            const { CommandHandler } = await import('../utils/CommandHandler.js');
            
            // Note: We need access to the client's command handler
            // For now, we'll just report success and note that restart may be needed
            const successEmbed = new EmbedBuilder()
                .setColor(0x00FF00)
                .setTitle('✅ Command Generated Successfully!')
                .setDescription(`Generated command file: \`${result.fileName}\``)
                .addFields(
                    { name: '📝 Prompt', value: prompt.substring(0, 500), inline: false },
                    { name: '📁 File Path', value: `\`./commands/${result.fileName}\``, inline: true },
                    { name: '⚡ Status', value: 'File written to disk. The command will be available after the next reload or bot restart.', inline: true }
                )
                .setFooter({ text: 'Note: Hot-reload may require additional setup' })
                .setTimestamp();

            await interaction.editReply({ embeds: [successEmbed] });

        } catch (error) {
            console.error('Error generating command:', error);
            
            const errorEmbed = new EmbedBuilder()
                .setColor(0xFF0000)
                .setTitle('❌ Failed to Generate Command')
                .setDescription(`Error: ${error.message}`)
                .addFields({
                    name: '💡 Tip',
                    value: 'Make sure your prompt is clear and includes a command name like `/mycommand`',
                    inline: false
                })
                .setTimestamp();

            await interaction.editReply({ embeds: [errorEmbed] });
        }
    }
};
