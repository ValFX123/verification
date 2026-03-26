import { SlashCommandBuilder } from 'discord.js';

export default {
    data: new SlashCommandBuilder()
        .setName('ping')
        .setDescription('Replies with pong!'),
    
    async execute(interaction) {
        const sent = await interaction.reply({ content: '🏓 Pong!', fetchReply: true });
        const latency = sent.createdTimestamp - interaction.createdTimestamp;
        await interaction.editReply(`🏓 Pong! Latency: **${latency}ms**`);
    }
};
