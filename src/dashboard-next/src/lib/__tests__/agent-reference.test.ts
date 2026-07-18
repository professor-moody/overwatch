import { describe, expect, it } from 'vitest';
import {
  agentDisplayLabel,
  canonicalAgentTaskId,
  resolveAgentReference,
  type AgentReference,
} from '../agent-reference';

describe('agent reference resolution', () => {
  const agents: AgentReference[] = [
    { task_id: 'task-alpha', id: 'legacy-alpha', agent_label: 'shared', agent_id: 'old-alpha' },
    { task_id: 'task-bravo', id: 'legacy-bravo', agent_label: 'shared', agent_id: 'old-bravo' },
    { task_id: 'task-charlie', id: 'legacy-charlie', agent_label: 'charlie' },
  ];

  it('resolves an exact canonical task ID before any colliding legacy alias', () => {
    const withCollision = [
      ...agents,
      { task_id: 'task-delta', id: 'legacy-delta', agent_label: 'task-alpha' },
    ];

    expect(resolveAgentReference(withCollision, 'task-alpha')?.task_id).toBe('task-alpha');
  });

  it('accepts a unique legacy ID or label but never guesses an ambiguous label', () => {
    expect(resolveAgentReference(agents, 'legacy-bravo')?.task_id).toBe('task-bravo');
    expect(resolveAgentReference(agents, 'old-alpha')?.task_id).toBe('task-alpha');
    expect(resolveAgentReference(agents, 'charlie')?.task_id).toBe('task-charlie');
    expect(resolveAgentReference(agents, 'shared')).toBeNull();
    expect(resolveAgentReference(agents, 'missing')).toBeNull();
  });

  it('provides stable display and task fallbacks without rendering undefined', () => {
    expect(canonicalAgentTaskId({ id: 'legacy-task' })).toBe('legacy-task');
    expect(agentDisplayLabel({ task_id: 'task-only' })).toBe('task-only');
    expect(canonicalAgentTaskId({ task_id: '', id: 'legacy-task' })).toBe('legacy-task');
    expect(agentDisplayLabel({ agent_label: '', task_id: 'task-only' })).toBe('task-only');
    expect(agentDisplayLabel({})).toBe('Agent');
  });
});
