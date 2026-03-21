// ============================================================
// Overwatch — Live Dashboard Server
// HTTP + WebSocket server for real-time engagement visualization
// ============================================================

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { GraphEngine } from './graph-engine.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface DashboardEvent {
  type: 'graph_update' | 'agent_update' | 'objective_update' | 'full_state';
  timestamp: string;
  data: any;
}

export class DashboardServer {
  private httpServer: ReturnType<typeof createServer>;
  private wss: WebSocketServer;
  private engine: GraphEngine;
  private port: number;
  private clients: Set<WebSocket> = new Set();
  private dashboardHtml: string | null = null;

  constructor(engine: GraphEngine, port: number = 8384) {
    this.engine = engine;
    this.port = port;

    this.httpServer = createServer((req, res) => this.handleHttp(req, res));
    this.wss = new WebSocketServer({ server: this.httpServer });

    this.wss.on('connection', (ws) => {
      this.clients.add(ws);
      // Send full state on connect
      const state = this.engine.getState();
      const graph = this.engine.exportGraph();
      ws.send(JSON.stringify({
        type: 'full_state',
        timestamp: new Date().toISOString(),
        data: { state, graph },
      }));

      ws.on('close', () => {
        this.clients.delete(ws);
      });

      ws.on('error', () => {
        this.clients.delete(ws);
      });
    });
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.httpServer.on('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE') {
          console.error(`Dashboard port ${this.port} in use, skipping dashboard`);
          resolve();
        } else {
          reject(err);
        }
      });

      this.httpServer.listen(this.port, () => {
        console.error(`Dashboard running at http://localhost:${this.port}`);
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      for (const ws of this.clients) {
        ws.close();
      }
      this.clients.clear();
      this.wss.close(() => {
        this.httpServer.close(() => resolve());
      });
    });
  }

  broadcast(event: DashboardEvent): void {
    const msg = JSON.stringify(event);
    for (const ws of this.clients) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(msg);
      }
    }
  }

  // Called by GraphEngine after persist()
  onGraphUpdate(detail: { new_nodes?: string[]; new_edges?: string[]; inferred_edges?: string[] }): void {
    const state = this.engine.getState();
    const graph = this.engine.exportGraph();
    this.broadcast({
      type: 'graph_update',
      timestamp: new Date().toISOString(),
      data: { state, graph, detail },
    });
  }

  private handleHttp(req: IncomingMessage, res: ServerResponse): void {
    const url = req.url || '/';

    // CORS headers for local dev
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');

    if (url === '/' || url === '/index.html') {
      this.serveHtml(res);
    } else if (url === '/api/state') {
      this.serveState(res);
    } else if (url === '/api/graph') {
      this.serveGraph(res);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
  }

  private serveHtml(res: ServerResponse): void {
    if (!this.dashboardHtml) {
      try {
        // In compiled output, dashboard HTML is at dist/dashboard/index.html
        // relative to this file at dist/services/dashboard-server.js
        const htmlPath = join(__dirname, '..', 'dashboard', 'index.html');
        this.dashboardHtml = readFileSync(htmlPath, 'utf-8');
      } catch {
        // Fallback: try source path
        try {
          const htmlPath = join(__dirname, '..', '..', 'src', 'dashboard', 'index.html');
          this.dashboardHtml = readFileSync(htmlPath, 'utf-8');
        } catch {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Dashboard HTML not found');
          return;
        }
      }
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(this.dashboardHtml);
  }

  private serveState(res: ServerResponse): void {
    const state = this.engine.getState();
    const graph = this.engine.exportGraph();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ state, graph }));
  }

  private serveGraph(res: ServerResponse): void {
    const graph = this.engine.exportGraph();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(graph));
  }

  get address(): string {
    return `http://localhost:${this.port}`;
  }

  get clientCount(): number {
    return this.clients.size;
  }
}
