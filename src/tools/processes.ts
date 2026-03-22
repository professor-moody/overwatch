import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { ProcessTracker } from '../services/process-tracker.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerProcessTools(server: McpServer, tracker: ProcessTracker, engine: GraphEngine): void {
  const persistProcesses = (): void => {
    engine.setTrackedProcesses(tracker.serialize());
    engine.persist();
  };

  // ============================================================
  // Tool: track_process
  // Register a long-running scan/process for tracking
  // ============================================================
  server.registerTool(
    'track_process',
    {
      title: 'Track Process',
      description: `Register a long-running scan or process for tracking.

Use this after launching a scan (nmap, bloodhound-python, certipy, etc.) to track its PID.
The orchestrator will monitor whether the process is still running and report its status.

This helps coordinate async work — agents can check if their scans are done before
attempting to parse output.`,
      inputSchema: {
        pid: z.number().int().describe('Process ID of the running scan'),
        command: z.string().describe('Command that was executed'),
        description: z.string().describe('Human-readable description of what this scan does'),
        agent_id: z.string().optional().describe('Agent that launched this process'),
        target_node: z.string().optional().describe('Node ID being targeted by this scan'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    withErrorBoundary('track_process', async ({ pid, command, description, agent_id, target_node }) => {
      const proc = tracker.register({
        id: uuidv4(),
        pid,
        command,
        description,
        agent_id,
        target_node,
      });
      persistProcesses();

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            process_id: proc.id,
            pid: proc.pid,
            status: proc.status,
            message: `Tracking process ${pid}: ${description}`
          }, null, 2)
        }]
      };
    })
  );

  // ============================================================
  // Tool: check_processes
  // List tracked processes and their current status
  // ============================================================
  server.registerTool(
    'check_processes',
    {
      title: 'Check Tracked Processes',
      description: `List all tracked processes and their current status.

Automatically checks if running PIDs are still alive and updates status.
Use this to see if scans have completed before parsing their output.`,
      inputSchema: {
        active_only: z.boolean().default(false).describe('Only show currently running processes'),
        process_id: z.string().optional().describe('Check a specific tracked process by ID'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    withErrorBoundary('check_processes', async ({ active_only, process_id }) => {
      if (process_id) {
        const proc = tracker.get(process_id);
        if (!proc) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: `Process not found: ${process_id}` }, null, 2) }],
            isError: true,
          };
        }
        const changed = tracker.refreshStatuses();
        if (changed) persistProcesses();
        return {
          content: [{ type: 'text', text: JSON.stringify(tracker.get(process_id) || proc, null, 2) }],
        };
      }

      const changed = tracker.refreshStatuses();
      if (changed) persistProcesses();
      const all = tracker.listAll();
      const summary = {
        active: all.filter(p => p.status === 'running').length,
        completed: all.filter(p => p.status !== 'running').length,
        processes: all,
      };
      const processes = active_only
        ? summary.processes.filter(p => p.status === 'running')
        : summary.processes;

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            active: summary.active,
            completed: summary.completed,
            processes,
          }, null, 2)
        }]
      };
    })
  );
}
