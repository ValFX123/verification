import { SlashCommandBuilder, EmbedBuilder } from 'discord.js';

export default {
    data: new SlashCommandBuilder()
        .setName('help')
        .setDescription('Shows available commands and bot information'),
    
    async execute(interaction) {
        const embed = new EmbedBuilder()
            .setColor(0x5865F2)
            .setTitle('🤖 Self-Modifying Bot Help')
            .setDescription('This bot can generate its own commands using `/gwencode`!')
            .addFields(
                { name: '📌 Core Commands', value: '`/ping` - Check bot latency\n`/help` - Show this help menu\n`/gwencode` - Generate new commands' },
                { name: '⚡ Features', value: '• Hot-reload commands\n• Self-modifying code\n• VPS optimized\n• Owner-only protection' },
                { name: '💡 Usage', value: 'Use `/gwencode [prompt]` to create new commands!\nExample: "create a command that rolls dice"' }
            )
            .setFooter({ text: `Requested by ${interaction.user.tag}` })
            .setTimestamp();

        await interaction.reply({ embeds: [embed] });
    }
};
