import { useState, type RefObject } from 'react';
import * as api from '../../lib/api';
import type { ThreadEntry } from '../../lib/agent-thread';
import { threadHasOpenQuestion } from '../../lib/agent-thread';
import { useNavigation } from '../../hooks/useNavigation';
import { cn, formatTimestamp } from '../../lib/utils';
import { ActionButton, PanelSection, StatusPill } from '../shared/primitives';

// Phase 5b — the focused agent's CONVERSATION. Renders the buildAgentThread
// model (lib/agent-thread.ts, tested) as a readable back-and-forth: your
// commands, the agent's actions + results, findings, and inline-answerable
// questions — instead of a flat event log. Replaces the per-agent activity list
// when an agent is focused; the full-stream view keeps the threaded console.

export function AgentThread({
  agentLabel,
  entries,
  totalEntries,
  paused,
  following,
  scrollRef,
  onTogglePaused,
  onScroll,
  onJumpLatest,
  onRefresh,
  onAnswered,
  onNavigateGraph,
  onNavigatePanel,
}: {
  agentLabel: string;
  entries: ThreadEntry[];
  totalEntries: number;
  paused: boolean;
  following: boolean;
  scrollRef: RefObject<HTMLDivElement | null>;
  onTogglePaused: () => void;
  onScroll: () => void;
  onJumpLatest: () => void;
  onRefresh: () => void;
  onAnswered: () => void;
  onNavigateGraph: (nodeId: string) => void;
  onNavigatePanel: ReturnType<typeof useNavigation>['navigateToPanel'];
}) {
  const hasQuestion = threadHasOpenQuestion(entries);
  // Bounded live-tail region (see AgentOutputConsole): max-h keeps follow-to-top
  // scrolling inside this box rather than moving the whole page.
  return (
    <PanelSection className="flex max-h-[calc(100vh-11rem)] flex-col overflow-hidden p-0 border-accent/20">
      <div className="flex items-center justify-between gap-3 border-b border-border p-3">
        <div className="flex items-center gap-2">
          <h3 className="text-base font-semibold text-foreground">Conversation</h3>
          <span className="font-mono text-[11px] text-muted-foreground">{agentLabel}</span>
          <StatusPill tone={paused ? 'warning' : following ? 'success' : 'muted'}>
            {paused ? 'paused' : following ? 'following' : 'reading'}
          </StatusPill>
          {hasQuestion && <StatusPill tone="warning">awaiting your answer</StatusPill>}
        </div>
        <div className="flex flex-wrap justify-end gap-1.5">
          {!following && !paused && <ActionButton onClick={onJumpLatest} variant="ghost" size="xs">Jump to latest</ActionButton>}
          <ActionButton onClick={onTogglePaused} variant={paused ? 'warning' : 'secondary'} size="xs">{paused ? 'Resume' : 'Pause'}</ActionButton>
          <ActionButton onClick={onRefresh} variant="secondary" size="xs">Refresh</ActionButton>
        </div>
      </div>

      <div ref={scrollRef} onScroll={onScroll} className="min-h-0 flex-1 overflow-y-auto bg-background/30 p-3">
        {entries.length === 0 ? (
          <div className="flex h-full min-h-64 items-center justify-center rounded border border-dashed border-border text-sm text-muted-foreground">
            {totalEntries === 0 ? 'No conversation yet. Command the agent above; its actions, results, and questions appear here.' : 'No entries match the current filter.'}
          </div>
        ) : (
          <div className="space-y-2">
            {/* Newest first: buildAgentThread keeps the newest N in chronological
                order, so reverse only at render. Follow-to-top is handled by
                scrollConsoleToNewest (scrollTop = 0) on the scroll container. */}
            {entries.slice().reverse().map(entry => (
              <ThreadEntryRow
                key={entry.id}
                entry={entry}
                onAnswered={onAnswered}
                onNavigateGraph={onNavigateGraph}
                onNavigatePanel={onNavigatePanel}
              />
            ))}
          </div>
        )}
      </div>
    </PanelSection>
  );
}

function ThreadEntryRow({
  entry,
  onAnswered,
  onNavigateGraph,
  onNavigatePanel,
}: {
  entry: ThreadEntry;
  onAnswered: () => void;
  onNavigateGraph: (nodeId: string) => void;
  onNavigatePanel: ReturnType<typeof useNavigation>['navigateToPanel'];
}) {
  const [rawOpen, setRawOpen] = useState(false);

  // Secondary entries (thoughts, system notes, sessions) read as dim one-liners.
  if (entry.prominence === 'secondary') {
    return (
      <div className="flex items-start gap-2 px-1 text-[11px] text-muted-foreground">
        <span className="w-12 flex-shrink-0 font-mono text-[10px]">{formatTimestamp(entry.timestamp)}</span>
        <span className="truncate" title={entry.body || entry.title}>
          {entry.kind === 'thought' ? '· thinking: ' : '· '}{entry.body || entry.title}
        </span>
      </div>
    );
  }

  if (entry.kind === 'question') {
    return <QuestionEntry entry={entry} onAnswered={onAnswered} />;
  }

  const isOperator = entry.role === 'operator';
  const accent =
    entry.kind === 'finding' ? 'border-success/40 bg-success/5' :
    isOperator ? 'border-accent/40 bg-accent/5' :
    entry.severity === 'error' ? 'border-destructive/40' :
    'border-border bg-surface';

  return (
    <div className={cn('rounded border p-2.5 text-xs', accent, isOperator && 'ml-8')}>
      <div className="flex items-center gap-2">
        <span className={cn('text-[10px] font-medium uppercase tracking-wide', isOperator ? 'text-accent' : entry.kind === 'finding' ? 'text-success' : 'text-muted-foreground')}>
          {isOperator ? 'You' : entry.kind === 'finding' ? '🔎 Finding' : entry.title}
        </span>
        {entry.status && <span className="rounded bg-background px-1 py-0.5 text-[10px] text-muted-foreground">{entry.status}</span>}
        <span className="ml-auto flex-shrink-0 font-mono text-[10px] text-muted-foreground">{formatTimestamp(entry.timestamp)}</span>
      </div>
      <div className="mt-1 whitespace-pre-wrap break-words text-foreground/90">{entry.body || entry.title}</div>
      <ThreadLinks links={entry.links} onNavigateGraph={onNavigateGraph} onNavigatePanel={onNavigatePanel} />
      {entry.raw && (
        <div className="mt-1.5">
          <button onClick={() => setRawOpen(v => !v)} className="text-[10px] text-muted-foreground hover:text-foreground">
            {rawOpen ? 'Hide raw' : 'Raw'}
          </button>
          {rawOpen && (
            <pre className="mt-1 max-h-36 overflow-auto rounded bg-background p-2 text-[10px] text-muted-foreground">{JSON.stringify(entry.raw, null, 2)}</pre>
          )}
        </div>
      )}
    </div>
  );
}

function ThreadLinks({
  links,
  onNavigateGraph,
  onNavigatePanel,
}: {
  links?: ThreadEntry['links'];
  onNavigateGraph: (nodeId: string) => void;
  onNavigatePanel: ReturnType<typeof useNavigation>['navigateToPanel'];
}) {
  if (!links) return null;
  const chip = 'max-w-full truncate rounded bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-accent hover:bg-accent/20';
  const short = (v: string) => (v.length > 12 ? v.slice(0, 12) : v);
  return (
    <div className="mt-1.5 flex flex-wrap gap-1">
      {links.evidence_id && <button className={chip} onClick={() => onNavigatePanel('evidence')}>evidence {short(links.evidence_id)}</button>}
      {(links.finding_ids || []).slice(0, 2).map(id => (
        <button key={id} className={chip} onClick={() => onNavigatePanel('findings', id)}>finding {short(id)}</button>
      ))}
      {links.session_id && <button className={chip} onClick={() => onNavigatePanel('sessions', links.session_id)}>session {short(links.session_id)}</button>}
      {(links.node_ids || []).slice(0, 3).map(id => (
        <button key={id} className={chip} onClick={() => onNavigateGraph(id)}>{short(id)}</button>
      ))}
    </div>
  );
}

function QuestionEntry({ entry, onAnswered }: { entry: ThreadEntry; onAnswered: () => void }) {
  const [answer, setAnswer] = useState('');
  const [busy, setBusy] = useState(false);
  const send = async (value: string) => {
    const text = value.trim();
    if (!text || busy || !entry.queryId) return;
    setBusy(true);
    try {
      await api.answerAgentQuery(entry.queryId, text);
      onAnswered();
    } catch {
      setBusy(false); // keep the card so the operator can retry
    }
  };
  return (
    <div className="rounded border border-warning/50 bg-warning/5 p-2.5 text-xs">
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-medium uppercase tracking-wide text-warning">❓ Agent asks</span>
        <span className="ml-auto flex-shrink-0 font-mono text-[10px] text-muted-foreground">{formatTimestamp(entry.timestamp)}</span>
      </div>
      <div className="mt-1 whitespace-pre-wrap break-words text-foreground">{entry.body}</div>
      {entry.options && entry.options.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {entry.options.map((opt, i) => (
            <ActionButton key={i} size="xs" variant="secondary" disabled={busy} onClick={() => void send(opt)}>{opt}</ActionButton>
          ))}
        </div>
      )}
      <div className="mt-2 flex items-center gap-1.5">
        <input
          className="flex-1 rounded border border-border bg-background px-2 py-1 text-[11px] outline-none focus:border-accent"
          placeholder="Answer…"
          value={answer}
          onChange={e => setAnswer(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') void send(answer); }}
          disabled={busy}
        />
        <ActionButton size="xs" variant="success" disabled={busy || !answer.trim()} onClick={() => void send(answer)}>Answer</ActionButton>
      </div>
    </div>
  );
}
