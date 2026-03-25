// ============================================================
// Overwatch — Session Adapters
// SSH, LocalPTY, and Socket adapter implementations
// ============================================================

import * as pty from 'node-pty';
import { createServer, connect, type Server, type Socket } from 'net';
import type { AdapterHandle, SessionCapabilities } from '../types.js';
import type { SessionAdapterFactory } from './session-manager.js';

// ============================================================
// LocalPtyAdapter — spawns a local shell via node-pty
// ============================================================

const PTY_CAPABILITIES: SessionCapabilities = {
  has_stdin: true,
  has_stdout: true,
  supports_resize: true,
  supports_signals: true,
  tty_quality: 'full',
};

export class LocalPtyAdapter implements SessionAdapterFactory {
  readonly kind = 'local_pty' as const;

  async spawn(options: Record<string, unknown>): Promise<AdapterHandle> {
    const shell = (options.shell as string) || process.env.SHELL || '/bin/bash';
    const cols = (options.cols as number) || 120;
    const rows = (options.rows as number) || 30;
    const cwd = (options.cwd as string) || process.cwd();
    const env = (options.env as Record<string, string>) || { ...process.env as Record<string, string> };

    const proc = pty.spawn(shell, [], {
      name: 'xterm-256color',
      cols,
      rows,
      cwd,
      env,
    });

    const dataCallbacks: Array<(chunk: string) => void> = [];
    const exitCallbacks: Array<(info: { exitCode?: number; signal?: number }) => void> = [];

    proc.onData((data: string) => {
      for (const cb of dataCallbacks) cb(data);
    });

    proc.onExit((e: { exitCode: number; signal?: number }) => {
      for (const cb of exitCallbacks) cb({ exitCode: e.exitCode, signal: e.signal });
    });

    const handle: AdapterHandle = {
      pid: proc.pid,
      capabilities: { ...PTY_CAPABILITIES },
      write(data: string) {
        proc.write(data);
      },
      resize(cols: number, rows: number) {
        proc.resize(cols, rows);
      },
      kill(signal?: string) {
        proc.kill(signal);
      },
      close() {
        proc.kill();
      },
      onData(cb: (chunk: string) => void) {
        dataCallbacks.push(cb);
      },
      onExit(cb: (info: { exitCode?: number; signal?: number }) => void) {
        exitCallbacks.push(cb);
      },
    };

    return handle;
  }
}

// ============================================================
// SshAdapter — spawns ssh via node-pty
// ============================================================

export class SshAdapter implements SessionAdapterFactory {
  readonly kind = 'ssh' as const;

  async spawn(options: Record<string, unknown>): Promise<AdapterHandle> {
    const host = options.host as string;
    if (!host) throw new Error('SSH adapter requires a host');

    const user = options.user as string | undefined;
    const port = options.port as number | undefined;
    const keyPath = options.key_path as string | undefined;
    const password = options.password as string | undefined;
    const sshOptions = (options.ssh_options as string[]) || [];
    const cols = (options.cols as number) || 120;
    const rows = (options.rows as number) || 30;

    const args: string[] = [];

    // Disable host key checking in engagement contexts (operator's choice)
    // Can be overridden via ssh_options
    if (!sshOptions.some(o => o.includes('StrictHostKeyChecking'))) {
      args.push('-o', 'StrictHostKeyChecking=no');
    }
    if (!sshOptions.some(o => o.includes('UserKnownHostsFile'))) {
      args.push('-o', 'UserKnownHostsFile=/dev/null');
    }

    if (port) {
      args.push('-p', String(port));
    }
    if (keyPath) {
      args.push('-i', keyPath);
    }

    // Add custom SSH options
    for (const opt of sshOptions) {
      args.push('-o', opt);
    }

    // Build target
    const target = user ? `${user}@${host}` : host;
    args.push(target);

    // If password is provided, use sshpass if available
    let command = 'ssh';
    const spawnArgs = args;
    if (password) {
      command = 'sshpass';
      spawnArgs.unshift('-p', password, 'ssh');
    }

    const proc = pty.spawn(command, spawnArgs, {
      name: 'xterm-256color',
      cols,
      rows,
      env: { ...process.env as Record<string, string> },
    });

    const dataCallbacks: Array<(chunk: string) => void> = [];
    const exitCallbacks: Array<(info: { exitCode?: number; signal?: number }) => void> = [];

    proc.onData((data: string) => {
      for (const cb of dataCallbacks) cb(data);
    });

    proc.onExit((e: { exitCode: number; signal?: number }) => {
      for (const cb of exitCallbacks) cb({ exitCode: e.exitCode, signal: e.signal });
    });

    const handle: AdapterHandle = {
      pid: proc.pid,
      capabilities: { ...PTY_CAPABILITIES },
      write(data: string) {
        proc.write(data);
      },
      resize(cols: number, rows: number) {
        proc.resize(cols, rows);
      },
      kill(signal?: string) {
        proc.kill(signal);
      },
      close() {
        proc.kill();
      },
      onData(cb: (chunk: string) => void) {
        dataCallbacks.push(cb);
      },
      onExit(cb: (info: { exitCode?: number; signal?: number }) => void) {
        exitCallbacks.push(cb);
      },
    };

    return handle;
  }
}

// ============================================================
// SocketAdapter — wraps TCP socket (bind/reverse shell)
// ============================================================

const SOCKET_CAPABILITIES: SessionCapabilities = {
  has_stdin: true,
  has_stdout: true,
  supports_resize: false,
  supports_signals: false,
  tty_quality: 'dumb',
};

export class SocketAdapter implements SessionAdapterFactory {
  readonly kind = 'socket' as const;

  // Track active servers so they can be cleaned up
  private activeServers: Map<string, Server> = new Map();

  async spawn(options: Record<string, unknown>): Promise<AdapterHandle> {
    const mode = (options.mode as string) || 'connect';
    const host = options.host as string;
    const port = options.port as number;
    const sessionId = options.sessionId as string;
    const onConnect = options.onConnect as (() => void) | undefined;

    if (!port) throw new Error('Socket adapter requires a port');

    if (mode === 'listen') {
      return this.spawnListener(host || '0.0.0.0', port, sessionId, onConnect);
    } else {
      if (!host) throw new Error('Socket adapter connect mode requires a host');
      return this.spawnConnect(host, port, sessionId, onConnect);
    }
  }

  private spawnListener(host: string, port: number, sessionId: string, onConnect?: () => void): Promise<AdapterHandle> {
    return new Promise((resolve, reject) => {
      const dataCallbacks: Array<(chunk: string) => void> = [];
      const exitCallbacks: Array<(info: { exitCode?: number; signal?: number }) => void> = [];
      let activeSocket: Socket | null = null;
      let closed = false;

      const server = createServer((socket: Socket) => {
        // Accept only the first connection
        if (activeSocket) {
          socket.destroy();
          return;
        }
        activeSocket = socket;
        this.wireSocket(socket, dataCallbacks, exitCallbacks, () => { closed = true; });
        if (onConnect) onConnect();
      });

      server.on('error', (err: Error) => {
        if (!activeSocket) {
          reject(err);
        }
      });

      server.listen(port, host, () => {
        if (sessionId) this.activeServers.set(sessionId, server);

        const handle: AdapterHandle = {
          pid: undefined,
          capabilities: { ...SOCKET_CAPABILITIES },
          write(data: string) {
            if (!activeSocket || closed) throw new Error('Socket not connected');
            activeSocket.write(data);
          },
          close() {
            closed = true;
            if (activeSocket) {
              activeSocket.destroy();
              activeSocket = null;
            }
            server.close();
            if (sessionId) {
              // Use arrow to capture `this` from outer class, but we stored ref
            }
          },
          onData(cb: (chunk: string) => void) {
            dataCallbacks.push(cb);
          },
          onExit(cb: (info: { exitCode?: number; signal?: number }) => void) {
            exitCallbacks.push(cb);
          },
        };

        resolve(handle);
      });
    });
  }

  private spawnConnect(host: string, port: number, sessionId: string, onConnect?: () => void): Promise<AdapterHandle> {
    return new Promise((resolve, reject) => {
      const dataCallbacks: Array<(chunk: string) => void> = [];
      const exitCallbacks: Array<(info: { exitCode?: number; signal?: number }) => void> = [];
      let closed = false;

      const socket = connect({ host, port }, () => {
        if (onConnect) onConnect();

        const handle: AdapterHandle = {
          pid: undefined,
          capabilities: { ...SOCKET_CAPABILITIES },
          write(data: string) {
            if (closed) throw new Error('Socket closed');
            socket.write(data);
          },
          close() {
            closed = true;
            socket.destroy();
          },
          onData(cb: (chunk: string) => void) {
            dataCallbacks.push(cb);
          },
          onExit(cb: (info: { exitCode?: number; signal?: number }) => void) {
            exitCallbacks.push(cb);
          },
        };

        resolve(handle);
      });

      this.wireSocket(socket, dataCallbacks, exitCallbacks, () => { closed = true; });

      socket.on('error', (err: Error) => {
        if (!closed) {
          reject(err);
        }
      });
    });
  }

  private wireSocket(
    socket: Socket,
    dataCallbacks: Array<(chunk: string) => void>,
    exitCallbacks: Array<(info: { exitCode?: number; signal?: number }) => void>,
    onClose: () => void,
  ): void {
    socket.setEncoding('utf-8');

    socket.on('data', (data: Buffer | string) => {
      const chunk = typeof data === 'string' ? data : data.toString('utf-8');
      for (const cb of dataCallbacks) cb(chunk);
    });

    socket.on('close', () => {
      onClose();
      for (const cb of exitCallbacks) cb({ exitCode: 0 });
    });

    socket.on('error', () => {
      onClose();
      for (const cb of exitCallbacks) cb({ exitCode: 1 });
    });
  }

  cleanup(sessionId: string): void {
    const server = this.activeServers.get(sessionId);
    if (server) {
      server.close();
      this.activeServers.delete(sessionId);
    }
  }
}
