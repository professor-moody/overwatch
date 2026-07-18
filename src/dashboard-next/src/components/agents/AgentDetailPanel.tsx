import { useState } from 'react';
import type { AgentInfo, SessionInfo } from '../../lib/types';
import {
  agentDisplayLabel,
  canonicalAgentTaskId,
} from '../../lib/agent-reference';
import type { DirectiveKind } from '../../lib/api/agents';
import { cn, formatElapsed } from '../../lib/utils';
import { ActionButton, PanelSection, StatusPill } from '../shared/primitives';

export type AgentContext = {
  subgraph?: {
    nodes?: Array<{ id: string; properties?: Record<string, unknown> }>;
    edges?: unknown[];
  };
};

export interface AgentDetailPanelProps {
  agent: AgentInfo;
  context: AgentContext | null;
  ownedSessions: SessionInfo[];
  onCancel?: () => void;
  onForceRemove?: () => void;
  onNavigateGraph: (nodeId: string) => void;
  onNavigateCampaign: (campaignId: string) => void;
  onNavigateSession: (sessionId: string) => void;
  onIssueDirective: (taskId: string, kind: DirectiveKind) => Promise<void>;
}

export function AgentSteeringControls({
  taskId,
  onIssueDirective,
}: {
  taskId: string;
  onIssueDirective: AgentDetailPanelProps['onIssueDirective'];
}) {
  const [busy, setBusy] = useState<DirectiveKind | null>(null);

  const issue = async (kind: DirectiveKind) => {
    setBusy(kind);
    try {
      await onIssueDirective(taskId, kind);
    } catch {
      // The owner presents transport/application feedback; keep the button's
      // fire-and-forget event handler from producing an unhandled rejection.
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="mt-3">
      <div className="mb-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">Steer (cooperative)</div>
      <div className="flex flex-wrap gap-1.5">
        <ActionButton size="xs" variant="warning" disabled={busy !== null} onClick={() => void issue('pause')}>
          Pause
        </ActionButton>
        <ActionButton size="xs" variant="success" disabled={busy !== null} onClick={() => void issue('resume')}>
          Resume
        </ActionButton>
      </div>
    </div>
  );
}

export function AgentDetailPanel({
  agent,
  context,
  ownedSessions,
  onCancel,
  onForceRemove,
  onNavigateGraph,
  onNavigateCampaign,
  onNavigateSession,
  onIssueDirective,
}: AgentDetailPanelProps) {
  const taskId = canonicalAgentTaskId(agent);
  const label = agentDisplayLabel(agent);
  const elapsed = agent.elapsed_ms
    ? formatElapsed(agent.elapsed_ms)
    : agent.completed_at && agent.assigned_at
      ? formatElapsed(new Date(agent.completed_at).getTime() - new Date(agent.assigned_at).getTime())
      : '—';
  const subgraphNodes = context?.subgraph?.nodes ?? [];

  return (
    <PanelSection dense>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-foreground">{label}</h3>
          <p className="mt-0.5 break-all font-mono text-[10px] text-muted-foreground">{taskId}</p>
        </div>
        <StatusPill tone={agent.status === 'running' ? 'success' : agent.status === 'failed' ? 'danger' : agent.status === 'completed' ? 'accent' : 'muted'}>
          {agent.status}
        </StatusPill>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {onCancel && <ActionButton onClick={onCancel} size="xs" variant="danger">Cancel</ActionButton>}
        {onForceRemove && (
          <ActionButton
            onClick={onForceRemove}
            size="xs"
            variant="danger"
            title="Force stop & remove — kills the process and clears the agent even if Cancel won't"
          >
            Force remove
          </ActionButton>
        )}
        {ownedSessions.length > 0 && (
          <ActionButton onClick={() => onNavigateSession(ownedSessions[0].id)} size="xs" variant="secondary">
            Open session →{ownedSessions.length > 1 ? ` (${ownedSessions.length})` : ''}
          </ActionButton>
        )}
        {agent.campaign_id && (
          <ActionButton onClick={() => onNavigateCampaign(agent.campaign_id!)} size="xs" variant="ghost">
            Campaign
          </ActionButton>
        )}
      </div>

      {agent.status === 'running' && taskId && (
        <AgentSteeringControls taskId={taskId} onIssueDirective={onIssueDirective} />
      )}

      <div className="mt-4 space-y-2">
        {agent.status === 'running' && agent.current_action && <DetailRow label="Doing" value={agent.current_action} />}
        <DetailRow label="Elapsed" value={elapsed} />
        {agent.skill && <DetailRow label="Skill" value={agent.skill} />}
        {agent.frontier_item_id && <DetailRow label="Frontier" value={agent.frontier_item_id} mono />}
        {agent.result_summary && <DetailRow label="Result" value={agent.result_summary} />}
        <DetailRow label="Scope" value={`${(agent.subgraph_node_ids || agent.scope_node_ids || []).length} nodes`} />
      </div>

      {subgraphNodes.length > 0 && (
        <div className="mt-4">
          <div className="mb-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">Scoped Nodes</div>
          <div className="space-y-1">
            {subgraphNodes.slice(0, 12).map(node => (
              <button
                key={node.id}
                onClick={() => onNavigateGraph(node.id)}
                className="block w-full truncate rounded bg-elevated/60 px-2 py-1 text-left text-xs text-accent hover:bg-hover"
                title={node.id}
              >
                {String(node.properties?.label || node.id)}
              </button>
            ))}
            {subgraphNodes.length > 12 && (
              <div className="text-[10px] text-muted-foreground">and {subgraphNodes.length - 12} more</div>
            )}
          </div>
        </div>
      )}
    </PanelSection>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2 text-xs">
      <span className="w-24 flex-shrink-0 text-muted-foreground">{label}</span>
      <span className={cn('break-all text-foreground', mono && 'font-mono text-[10px]')}>{value}</span>
    </div>
  );
}
