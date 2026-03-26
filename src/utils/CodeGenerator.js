import { writeFile, unlink } from 'fs/promises';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

export class CodeGenerator {
    constructor() {
        this.commandsDir = join(__dirname, '..', 'commands');
    }

    /**
     * Generate a command file based on user prompt
     * In production, this would call Qwen API or similar
     * For now, it uses template-based generation
     */
    async generateCommand(prompt, commandName) {
        // Validate command name
        if (!/^[a-z0-9_-]+$/.test(commandName)) {
            throw new Error('Invalid command name. Use only lowercase letters, numbers, hyphens, and underscores.');
        }

        const fileName = `${commandName}.js`;
        const filePath = join(this.commandsDir, fileName);

        // Generate command code based on prompt keywords
        let commandCode = this.generateCommandTemplate(prompt, commandName);

        try {
            // Write the file
            await writeFile(filePath, commandCode, 'utf-8');
            console.log(`📝 Generated command file: ${fileName}`);
            
            return {
                success: true,
                fileName,
                filePath,
                commandName
            };
        } catch (error) {
            console.error('Failed to write command file:', error.message);
            throw error;
        }
    }

    /**
     * Generate command template based on prompt analysis
     */
    generateCommandTemplate(prompt, commandName) {
        const promptLower = prompt.toLowerCase();
        
        // Determine command type based on keywords
        let description = 'A dynamically generated command';
        let options = [];
        let responseType = 'reply';
        let responseContent = `Command **/${commandName}** executed successfully!`;

        // Analyze prompt for features
        if (promptLower.includes('ping')) {
            description = 'Replies with pong!';
            responseContent = '🏓 Pong!';
        } else if (promptLower.includes('ban') || promptLower.includes('kick')) {
            description = 'Moderation command to ban/kick a user';
            options = [{
                name: 'user',
                type: 'USER',
                description: 'The user to ban/kick',
                required: true
            }, {
                name: 'reason',
                type: 'STRING',
                description: 'Reason for the action',
                required: false
            }];
            responseType = 'moderation';
        } else if (promptLower.includes('say') || promptLower.includes('echo')) {
            description = 'Makes the bot say something';
            options = [{
                name: 'message',
                type: 'STRING',
                description: 'The message to say',
                required: true
            }];
            responseType = 'say';
        } else if (promptLower.includes('info') || promptLower.includes('server')) {
            description = 'Shows server information';
            responseType = 'embed';
        } else if (promptLower.includes('roll') || promptLower.includes('dice')) {
            description = 'Rolls a dice';
            options = [{
                name: 'sides',
                type: 'INTEGER',
                description: 'Number of sides on the dice',
                required: false
            }];
            responseType = 'random';
        }

        // Build the command code
        const optionsCode = options.map(opt => this.buildOptionCode(opt)).join(',\n        ');
        const executeCode = this.buildExecuteCode(responseType, commandName, responseContent);

        return `import { SlashCommandBuilder, EmbedBuilder } from 'discord.js';

export default {
    data: new SlashCommandBuilder()
        .setName('${commandName}')
        .setDescription('${description}')
        ${options.length > 0 ? `.addOptions(\n        ${optionsCode}\n        )` : ''},
    
    async execute(interaction) {
${executeCode}
    }
};
`;
    }

    buildOptionCode(option) {
        const typeMap = {
            'USER': 'User',
            'STRING': 'String',
            'INTEGER': 'Integer',
            'BOOLEAN': 'Boolean',
            'CHANNEL': 'Channel',
            'ROLE': 'Role'
        };

        const method = `add${typeMap[option.type] || 'String'}Option`;
        return `${method}('${option.name}', '${option.description}'${option.required ? ', true' : ''})`;
    }

    buildExecuteCode(type, commandName, defaultResponse) {
        switch (type) {
            case 'reply':
                return `        await interaction.reply('${defaultResponse}');`;
            
            case 'say':
                return `        const message = interaction.options.getString('message');
        await interaction.reply(message);`;
            
            case 'embed':
                return `        const embed = new EmbedBuilder()
            .setColor(0x5865F2)
            .setTitle('${commandName.charAt(0).toUpperCase() + commandName.slice(1)} Info')
            .setDescription('This is a dynamically generated command.')
            .setTimestamp();
        
        await interaction.reply({ embeds: [embed] });`;
            
            case 'random':
                return `        const sides = interaction.options.getInteger('sides') || 6;
        const result = Math.floor(Math.random() * sides) + 1;
        await interaction.reply(\`🎲 You rolled a **\${result}** on a \${sides}-sided die!\`);`;
            
            case 'moderation':
                return `        const user = interaction.options.getUser('user', true);
        const reason = interaction.options.getString('reason') || 'No reason provided';
        
        // Note: Actual moderation logic should be implemented based on bot permissions
        await interaction.reply(\`Action taken on \${user.tag}.\nReason: \${reason}\`);`;
            
            default:
                return `        await interaction.reply('${defaultResponse}');`;
        }
    }

    /**
     * Delete a faulty command file
     */
    async deleteCommand(fileName) {
        const filePath = join(this.commandsDir, fileName);
        try {
            await unlink(filePath);
            console.log(`🗑️  Deleted faulty command: ${fileName}`);
            return true;
        } catch (error) {
            console.error(`Failed to delete command ${fileName}:`, error.message);
            return false;
        }
    }

    /**
     * Simulate Qwen API call (placeholder for real implementation)
     */
    async callQwenAPI(prompt, apiKey, apiUrl) {
        // This is a placeholder - in production, implement actual API call
        /*
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: 'qwen-turbo',
                messages: [{
                    role: 'user',
                    content: `Generate a Discord.js slash command based on: ${prompt}`
                }]
            })
        });
        return await response.json();
        */
        
        // Return simulated response
        return {
            choices: [{
                message: {
                    content: this.generateCommandTemplate(prompt, 'generated')
                }
            }]
        };
    }
}

export default CodeGenerator;
