import { z } from 'zod';
import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { GraphEngine } from '../services/graph-engine.js';
import type { ProcessTracker } from '../services/process-tracker.js';
import { withErrorBoundary } from './error-boundary.js';
import {
  currentDaemonOwner,
  observeProcessIdentity,
  processIsAlive,
} from '../services/process-identity.js';

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
        pid: z.number().int().positive().describe('Process ID of the running scan'),
        command: z.string().describe('Command that was executed'),
        description: z.string().describe('Human-readable description of what this scan does'),
        task_id: z.string().optional().describe('Canonical owning task ID'),
        action_id: z.string().optional().describe('Action lifecycle ID associated with this process'),
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
    withErrorBoundary('track_process', async ({
      pid,
      command,
      description,
      task_id,
      action_id,
      agent_id,
      target_node,
    }) => {
      if (!Number.isSafeInteger(pid) || pid <= 0) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: 'pid must be a positive integer' }, null, 2),
          }],
          isError: true,
        };
      }
      const ownerReference = task_id ?? agent_id;
      const ownerResolution = ownerReference
        ? engine.resolveAgentTaskReference(ownerReference)
        : { status: 'missing' as const };
      if (ownerResolution.status === 'ambiguous_legacy_label') {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: `Agent label is ambiguous: ${ownerReference}`,
              candidate_task_ids: ownerResolution.candidate_task_ids,
            }, null, 2),
          }],
          isError: true,
        };
      }
      const ownerTask = ownerResolution.status === 'exact'
        || ownerResolution.status === 'unique_legacy_label'
        ? ownerResolution.task
        : undefined;
      const processId = uuidv4();
      const alive = processIsAlive(pid);
      const identity = observeProcessIdentity(pid);
      const recoveryWarning = !alive
        ? 'The adopted process is no longer running; its terminal outcome is unknown.'
        : !identity.process_start_identity
          ? 'The adopted process is alive but its physical identity cannot be verified.'
          : undefined;
      engine.reserveRuntimeRun({
        run_id: processId,
        kind: 'tracked_process',
        task_id: ownerTask?.task_id ?? ownerTask?.id ?? task_id,
        action_id,
        agent_id: ownerTask?.agent_label ?? ownerTask?.agent_id ?? agent_id,
        daemon_owner: currentDaemonOwner(),
        command_fingerprint: createHash('sha256').update(command).digest('hex'),
        ownership_mode: 'external_adopted',
        signal_scope: 'none',
      });
      engine.acknowledgeRuntimeRunOwnership(processId, identity);
      engine.markRuntimeRunLaunched(processId, pid);
      if (recoveryWarning) {
        engine.finalizeRuntimeRun({
          run_id: processId,
          lifecycle: 'unknown',
          recovery_warning: recoveryWarning,
        });
      }
      let proc;
      try {
        proc = tracker.register({
          id: processId,
          pid,
          command,
          description,
          task_id: ownerTask?.task_id ?? ownerTask?.id ?? task_id,
          action_id,
          agent_id: ownerTask?.agent_label ?? ownerTask?.agent_id ?? agent_id,
          target_node,
          process_group_id: identity.process_group_id,
          process_start_identity: identity.process_start_identity,
          ownership_token: identity.ownership_token,
          daemon_owner: currentDaemonOwner(),
          command_fingerprint: createHash('sha256').update(command).digest('hex'),
          ownership_mode: 'external_adopted',
          signal_scope: 'none',
        }, recoveryWarning
          ? { status: 'unknown', recovery_warning: recoveryWarning }
          : {});
        persistProcesses();
      } catch (error) {
        engine.finalizeRuntimeRun({
          run_id: processId,
          lifecycle: 'failed',
          recovery_warning: `External process tracking registration failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        });
        throw error;
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            process_id: proc.id,
            run_id: proc.id,
            pid: proc.pid,
            status: proc.status,
            ownership_mode: 'external_adopted',
            signal_scope: 'none',
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
