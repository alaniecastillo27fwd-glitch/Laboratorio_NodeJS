import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const backendDir = path.resolve(rootDir, 'backend');
const frontendDir = path.resolve(rootDir, 'frontend');

/**
 * Comprueba si el puerto 3000 del backend ya está activo.
 */
const isPortOpen = (port) =>
  new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(600);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, '127.0.0.1');
  });

const main = async () => {
  const backendAlreadyRunning = await isPortOpen(3000);
  let backendProc = null;

  if (!backendAlreadyRunning) {
    console.log('[SecureVault] Iniciando servidor Backend (/backend) en http://localhost:3000 ...');
    backendProc = spawn(process.execPath, ['server.js'], {
      cwd: backendDir,
      stdio: 'inherit',
    });
  } else {
    console.log('[SecureVault] Servidor Backend ya detectado en http://localhost:3000');
  }

  const viteBin = path.resolve(frontendDir, 'node_modules', 'vite', 'bin', 'vite.js');
  const viteProc = spawn(process.execPath, [viteBin], {
    cwd: frontendDir,
    stdio: 'inherit',
  });

  const cleanup = () => {
    if (backendProc && !backendProc.killed) {
      backendProc.kill();
    }
    if (viteProc && !viteProc.killed) {
      viteProc.kill();
    }
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  viteProc.on('exit', cleanup);
};

main();
