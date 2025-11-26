import { spawn } from 'child_process';
import fs from 'fs';

let processNode;

function startServer() {
    if (processNode) processNode.kill();

    processNode = spawn('node', ['app.js'], { stdio: 'inherit' });
    console.log('🚀 Server started...');
}

fs.watch('.', { recursive: true }, (eventType, filename) => {
    if (!filename.includes('node_modules') && filename.endsWith('.js')) {
        console.log(`\n🔄 Change detected in ${filename}. Restarting server...`);
        startServer();
    }
});

startServer();