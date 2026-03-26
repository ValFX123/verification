import { Collection } from 'discord.js';
import { readdir, stat } from 'fs/promises';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

export class CommandHandler {
    constructor(client) {
        this.client = client;
        this.commands = new Collection();
        this.commandFiles = new Map(); // Track file paths for hot-reloading
    }

    async loadCommands(commandsDir = './commands') {
        const commandsPath = join(__dirname, '..', commandsDir);
        
        try {
            const files = await readdir(commandsPath);
            
            for (const file of files) {
                if (!file.endsWith('.js')) continue;
                
                const filePath = join(commandsPath, file);
                const stats = await stat(filePath);
                
                if (!stats.isFile()) continue;
                
                try {
                    // Clear cache for hot-reload
                    const modulePath = `file://${filePath}`;
                    
                    // Dynamic import with cache busting
                    const commandModule = await import(`${modulePath}?update=${Date.now()}`);
                    const command = commandModule.default;
                    
                    if (command && command.data && command.execute) {
                        this.commands.set(command.data.name, command);
                        this.commandFiles.set(command.data.name, filePath);
                        console.log(`✅ Loaded command: ${command.data.name}`);
                    } else {
                        console.warn(`⚠️  Command file ${file} missing required exports`);
                    }
                } catch (error) {
                    console.error(`❌ Failed to load command ${file}:`, error.message);
                    // Delete faulty file
                    try {
                        await import('fs/promises').then(fs => fs.unlink(filePath));
                        console.error(`🗑️  Deleted faulty command file: ${file}`);
                    } catch (delError) {
                        console.error(`Failed to delete faulty file:`, delError.message);
                    }
                }
            }
            
            return this.commands.size;
        } catch (error) {
            console.error('Failed to load commands directory:', error.message);
            return 0;
        }
    }

    async reloadCommand(commandName) {
        const filePath = this.commandFiles.get(commandName);
        if (!filePath) return false;

        try {
            const modulePath = `file://${filePath}`;
            
            // Clear require cache (for CommonJS compatibility)
            if (require.cache) {
                const resolvedPath = fileURLToPath(modulePath.split('?')[0]);
                delete require.cache[resolvedPath];
            }

            // Re-import the module
            const commandModule = await import(`${modulePath}?reload=${Date.now()}`);
            const command = commandModule.default;

            if (command && command.data && command.execute) {
                this.commands.set(command.data.name, command);
                console.log(`🔄 Reloaded command: ${commandName}`);
                return true;
            }
            return false;
        } catch (error) {
            console.error(`Failed to reload command ${commandName}:`, error.message);
            return false;
        }
    }

    getCommand(name) {
        return this.commands.get(name);
    }

    getAllCommands() {
        return this.commands.map(cmd => cmd.data.toJSON());
    }
}

export default CommandHandler;
