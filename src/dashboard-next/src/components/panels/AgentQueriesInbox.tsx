import { useState, useEffect, useCallback, useRef } from 'react';
import * as api from '../../lib/api';
import { POLL } from '../../lib/polling';
import { ActionButton } from '../shared/primitives';

// Phase 3D — agent→operator escalation inbox. A running agent that hits a fork
// can ask the operator a question (ask_operator) and wait; this surfaces those
// questions so the operator can answer. The answer reaches the agent on its next
// heartbeat. Live via the WS 'agent_query' push, with a poll fallback.

function QueryCard({ query, onAnswered }: { query: api.AgentQuery; onAnswered: () => void }) {
  const [answer, setAnswer] = useState('');
  const [busy, setBusy] = useState(false);
  const send = useCallback(async (value: string) => {
    const text = value.trim();
    if (!text || busy) return;
    setBusy(true);
    try {
      await api.answerAgentQuery(query.query_id, text);
      onAnswered();
    } catch {
      setBusy(false); // keep the card so the operator can retry
    }
  }, [busy, query.query_id, onAnswered]);

  return (
    <div className="rounded border border-warning/40 bg-warning/5 p-2 text-xs space-y-2">
      <div className="flex items-start justify-between gap-2">
        <span className="text-foreground">{query.question}</span>
        {query.agent_id && <span className="flex-shrink-0 font-mono text-[10px] text-muted-foreground">{query.agent_id}</span>}
      </div>
      {query.options && query.options.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {query.options.map((opt, i) => (
            <ActionButton key={i} size="xs" variant="secondary" disabled={busy} onClick={() => void send(opt)}>{opt}</ActionButton>
          ))}
        </div>
      )}
      <div className="flex items-center gap-1.5">
        <input
          className="flex-1 rounded border border-border bg-surface px-2 py-1 text-[11px] outline-none focus:border-accent"
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

export function AgentQueriesInbox() {
  const [queries, setQueries] = useState<api.AgentQuery[]>([]);
  const mounted = useRef(true);

  const load = useCallback(async () => {
    try {
      const { queries } = await api.getAgentQueries();
      if (mounted.current) setQueries(queries || []);
    } catch { /* transient */ }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void load();
    const onUpdate = () => void load();
    window.addEventListener('overwatch-agent-query-update', onUpdate);
    const timer = setInterval(() => void load(), POLL.AGENTS_MS);
    return () => {
      mounted.current = false;
      window.removeEventListener('overwatch-agent-query-update', onUpdate);
      clearInterval(timer);
    };
  }, [load]);

  if (queries.length === 0) return null;

  return (
    <div className="rounded-md border border-warning/40 bg-warning/5 p-3 space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-warning">⚠ Agent questions</span>
        <span className="rounded-full bg-warning/20 px-1.5 text-[10px] text-warning">{queries.length}</span>
        <span className="text-[10px] text-muted-foreground">agents are waiting on your answer</span>
      </div>
      <div className="space-y-2">
        {queries.map(q => <QueryCard key={q.query_id} query={q} onAnswered={load} />)}
      </div>
    </div>
  );
}
