import { describe, expect, it } from 'vitest';
import { dispatchedAgentLabel } from '../api';

describe('dispatchedAgentLabel', () => {
  it('prefers the canonical agent label', () => {
    expect(dispatchedAgentLabel({
      task_id: 'task-1',
      agent_label: 'planner-1',
      id: 'legacy-task-1',
      agent_id: 'legacy-planner-1',
    })).toBe('planner-1');
  });

  it('falls back across legacy aliases without rendering undefined', () => {
    expect(dispatchedAgentLabel({ task_id: 'task-2' })).toBe('task-2');
    expect(dispatchedAgentLabel(undefined)).toBe('Agent queued');
  });
});
