// ============================================================
// Overwatch — Session Adapters
// SSH, LocalPTY, and Socket adapter implementations
// ============================================================

// node-pty is an OPTIONAL native dependency, loaded dynamically. It is typed
// LOCALLY (not `typeof import('node-pty')`) and imported through a NON-LITERAL
// specifier, so `tsc` does not need the package installed to BUILD — a fresh
// clone without native build tools (a common node-pty compile failure) still
// compiles. LocalPtyAdapter/SshAdapter throw a clear error at runtime if it's
// genuinely missing.
type NodePty = { spawn: (file: string, args: string[] | string, opts: Record<string, unknown>) => any };
let pty: NodePty | null = null;
try {
  const specifier = 'node-pty';
  pty = (await import(specifier)) as unknown as NodePty;
} catch {
  // node-pty not installed — the PTY adapters throw at runtime
}
import { createServer, connect, type Server, type Socket } from 'net';
import type { AdapterHandle, SessionCapabilities } from '../types.js';
import type { SessionAdapterFactory } from './session-manager.js';

function adapterAbortSignal(options: Record<string, unknown>): AbortSignal | undefined {
  const signal = options.abort_signal;
  return signal && typeof signal === 'object' && 'aborted' in signal
    ? signal as AbortSignal
    : undefined;
}

function adapterAbortError(signal?: AbortSignal): Error {
  if (signal?.reason instanceof Error) return signal.reason;
  return new Error('Session adapter spawn aborted');
}

function throwIfAdapterAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw adapterAbortError(signal);
}

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
    const abortSignal = adapterAbortSignal(options);
    throwIfAdapterAborted(abortSignal);
    if (!pty) {
      throw new Error('node-pty is not installed. Install it with: npm install node-pty (requires native build tools)');
    }
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
      abortSignal?.removeEventListener('abort', onAbort);
      for (const cb of exitCallbacks) cb({ exitCode: e.exitCode, signal: e.signal });
    });

    const onAbort = (): void => {
      try { proc.kill(); } catch { /* best-effort persistence freeze */ }
    };
    if (abortSignal?.aborted) onAbort();
    else abortSignal?.addEventListener('abort', onAbort, { once: true });

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
        abortSignal?.removeEventListener('abort', onAbort);
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
    const abortSignal = adapterAbortSignal(options);
    throwIfAdapterAborted(abortSignal);
    if (!pty) {
      throw new Error('node-pty is not installed. Install it with: npm install node-pty (requires native build tools)');
    }
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

    // If password is provided, use sshpass with env var (-e) to avoid leaking in /proc/cmdline
    let command = 'ssh';
    const spawnArgs = args;
    const spawnEnv: Record<string, string> = { ...process.env as Record<string, string> };
    if (password) {
      command = 'sshpass';
      spawnArgs.unshift('-e', 'ssh');
      spawnEnv.SSHPASS = password;
    }

    const proc = pty.spawn(command, spawnArgs, {
      name: 'xterm-256color',
      cols,
      rows,
      env: spawnEnv,
    });

    const dataCallbacks: Array<(chunk: string) => void> = [];
    const exitCallbacks: Array<(info: { exitCode?: number; signal?: number }) => void> = [];

    proc.onData((data: string) => {
      for (const cb of dataCallbacks) cb(data);
    });

    proc.onExit((e: { exitCode: number; signal?: number }) => {
      abortSignal?.removeEventListener('abort', onAbort);
      for (const cb of exitCallbacks) cb({ exitCode: e.exitCode, signal: e.signal });
    });

    const onAbort = (): void => {
      try { proc.kill(); } catch { /* best-effort persistence freeze */ }
    };
    if (abortSignal?.aborted) onAbort();
    else abortSignal?.addEventListener('abort', onAbort, { once: true });

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
        abortSignal?.removeEventListener('abort', onAbort);
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
    const abortSignal = adapterAbortSignal(options);
    throwIfAdapterAborted(abortSignal);
    const mode = (options.mode as string) || 'connect';
    const host = (options.bind_host as string | undefined) || (options.host as string);
    const port = options.port as number;
    const sessionId = options.sessionId as string;
    const onConnect = options.onConnect as (() => void) | undefined;
    const acceptMode = (options.accept_mode as 'single' | 'rearm' | undefined) || 'single';

    if (mode === 'listen') {
      if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
        throw new Error('Socket adapter requires a port from 0 through 65535');
      }
      const bindHost = host || '127.0.0.1';
      if (bindHost === '0.0.0.0') {
        console.error(`[session] Warning: listener binding to 0.0.0.0 — exposed on all interfaces`);
      }
      return this.spawnListener(bindHost, port, sessionId, acceptMode, onConnect, abortSignal);
    } else {
      if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
        throw new Error('Socket adapter requires a port');
      }
      if (!host) throw new Error('Socket adapter connect mode requires a host');
      return this.spawnConnect(host, port, sessionId, onConnect, abortSignal);
    }
  }

  private spawnListener(
    host: string,
    port: number,
    sessionId: string,
    acceptMode: 'single' | 'rearm',
    onConnect?: () => void,
    abortSignal?: AbortSignal,
  ): Promise<AdapterHandle> {
    const self = this;
    return new Promise((resolve, reject) => {
      const dataCallbacks: Array<(chunk: string) => void> = [];
      const exitCallbacks: Array<(info: { exitCode?: number; signal?: number }) => void> = [];
      const disconnectCallbacks: Array<(info?: { reason?: string }) => void> = [];
      let activeSocket: Socket | null = null;
      let closed = false;
      let settled = false;

      const removeAbortListener = (): void => abortSignal?.removeEventListener('abort', onAbort);
      const closeTransport = (): void => {
        closed = true;
        if (activeSocket) {
          activeSocket.destroy();
          activeSocket = null;
        }
        try { server.close(); } catch { /* best-effort */ }
        if (sessionId) self.activeServers.delete(sessionId);
      };
      const onAbort = (): void => {
        closeTransport();
        if (!settled) {
          settled = true;
          reject(adapterAbortError(abortSignal));
        }
      };

      const server = createServer((socket: Socket) => {
        // Accept only one active connection at a time. Rearm mode keeps the
        // listener alive after the accepted shell disconnects.
        if (activeSocket) {
          socket.destroy();
          return;
        }
        activeSocket = socket;
        this.wireSocket(
          socket,
          dataCallbacks,
          acceptMode === 'rearm' ? [] : exitCallbacks,
          () => {
            activeSocket = null;
            if (acceptMode === 'rearm' && !closed) {
              for (const cb of disconnectCallbacks) cb({ reason: 'socket_closed' });
              return;
            }
            closed = true;
            try { server.close(); } catch { /* best-effort */ }
            if (sessionId) self.activeServers.delete(sessionId);
            removeAbortListener();
          },
        );
        if (onConnect) onConnect();
      });

      server.on('error', (err: Error) => {
        if (!activeSocket && !settled) {
          settled = true;
          removeAbortListener();
          reject(err);
        }
      });

      server.listen(port, host, () => {
        if (settled || abortSignal?.aborted) {
          onAbort();
          return;
        }
        settled = true;
        if (sessionId) this.activeServers.set(sessionId, server);

        const handle: AdapterHandle = {
          pid: undefined,
          capabilities: { ...SOCKET_CAPABILITIES },
          write(data: string) {
            if (!activeSocket || closed) throw new Error('Socket not connected');
            activeSocket.write(data);
          },
          close() {
            removeAbortListener();
            closeTransport();
          },
          onData(cb: (chunk: string) => void) {
            dataCallbacks.push(cb);
          },
          onExit(cb: (info: { exitCode?: number; signal?: number }) => void) {
            exitCallbacks.push(cb);
          },
          onDisconnect(cb: (info?: { reason?: string }) => void) {
            disconnectCallbacks.push(cb);
          },
        };

        resolve(handle);
      });
      if (abortSignal?.aborted) onAbort();
      else abortSignal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  private spawnConnect(
    host: string,
    port: number,
    _sessionId: string,
    onConnect?: () => void,
    abortSignal?: AbortSignal,
  ): Promise<AdapterHandle> {
    return new Promise((resolve, reject) => {
      const dataCallbacks: Array<(chunk: string) => void> = [];
      const exitCallbacks: Array<(info: { exitCode?: number; signal?: number }) => void> = [];
      let closed = false;
      // Whether this connect promise has settled. Keyed separately from `closed`
      // because wireSocket's own 'error' handler sets closed=true and is registered
      // BEFORE the reject handler below — so a `!closed` guard there would already be
      // false on a refused connection, and the promise would hang (open_session forever).
      let settled = false;

      // Buffer early data arriving before onData is registered by the caller
      const earlyBuffer: string[] = [];
      dataCallbacks.push((chunk: string) => { earlyBuffer.push(chunk); });

      const socket = connect({ host, port }, () => {
        if (settled) return; // an error already rejected — don't also resolve
        if (abortSignal?.aborted) {
          onAbort();
          return;
        }
        settled = true;
        if (onConnect) onConnect();

        const handle: AdapterHandle = {
          pid: undefined,
          capabilities: { ...SOCKET_CAPABILITIES },
          write(data: string) {
            if (closed) throw new Error('Socket closed');
            socket.write(data);
          },
          close() {
            abortSignal?.removeEventListener('abort', onAbort);
            closed = true;
            socket.destroy();
          },
          onData(cb: (chunk: string) => void) {
            // Remove the early buffer callback on first real registration
            if (earlyBuffer.length > 0 && dataCallbacks[0] !== cb) {
              dataCallbacks.length = 0;
            }
            dataCallbacks.push(cb);
            // Flush buffered early data to the new callback
            for (const chunk of earlyBuffer) cb(chunk);
            earlyBuffer.length = 0;
          },
          onExit(cb: (info: { exitCode?: number; signal?: number }) => void) {
            exitCallbacks.push(cb);
          },
        };

        resolve(handle);
      });

      const onAbort = (): void => {
        closed = true;
        socket.destroy();
        if (!settled) {
          settled = true;
          reject(adapterAbortError(abortSignal));
        }
      };
      if (abortSignal?.aborted) onAbort();
      else abortSignal?.addEventListener('abort', onAbort, { once: true });

      this.wireSocket(socket, dataCallbacks, exitCallbacks, () => {
        closed = true;
        abortSignal?.removeEventListener('abort', onAbort);
      });

      socket.on('error', (err: Error) => {
        // Reject only if the connect callback hasn't resolved yet. A post-connect
        // error is reported via wireSocket's exit callbacks, not by rejecting here.
        if (!settled) {
          settled = true;
          abortSignal?.removeEventListener('abort', onAbort);
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
    let exited = false;

    socket.on('data', (data: Buffer | string) => {
      const chunk = typeof data === 'string' ? data : data.toString('utf-8');
      for (const cb of dataCallbacks) cb(chunk);
    });

    socket.on('close', () => {
      if (exited) return;
      exited = true;
      onClose();
      for (const cb of exitCallbacks) cb({ exitCode: 0 });
    });

    socket.on('error', () => {
      if (exited) return;
      exited = true;
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
