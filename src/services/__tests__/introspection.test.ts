import { describe, it, expect } from 'vitest';
import { explainAction } from '../introspection.js';
import type { ActivityLogEntry } from '../engine-context.js';

function ev(o: Partial<ActivityLogEntry> & { event_id: string; timestamp: string; description: string }): ActivityLogEntry {
  return o as ActivityLogEntry;
}

describe('explainAction (P3.2)', () => {
  it('returns found:false for an unknown action_id', () => {
    const r = explainAction([], 'no-such-action');
    expect(r.found).toBe(false);
    expect(r.log_thought_chain).toEqual([]);
  });

  it('aggregates frontier_item_id, agent_id, and the thought chain', () => {
    const history = [
      ev({
        event_id: 'e1', timestamp: '2026-01-01T10:00:00Z',
        description: 'agent registered', event_type: 'agent_registered',
        action_id: 'a-1', agent_id: 'alice', frontier_item_id: 'fi-X',
      }),
      ev({
        event_id: 'e2', timestamp: '2026-01-01T10:00:01Z',
        description: 'thinking through options',
        event_type: 'thought', action_id: 'a-1', agent_id: 'alice',
        details: {
          kind: 'decision',
          considered_alternatives: ['nmap -sV', 'enum4linux', 'rpcclient'],
          confidence: 0.7,
        },
      }),
      ev({
        event_id: 'e3', timestamp: '2026-01-01T10:00:02Z',
        description: 'second thought',
        event_type: 'thought', action_id: 'a-1', agent_id: 'alice',
        details: {
          kind: 'reflection',
          related_action_ids: ['prior-act-A', 'prior-act-B'],
          considered_alternatives: ['enum4linux'], // duplicate; should dedupe
        },
      }),
    ];
    const r = explainAction(history, 'a-1');
    expect(r.found).toBe(true);
    expect(r.agent_id).toBe('alice');
    expect(r.frontier_item_id).toBe('fi-X');
    expect(r.log_thought_chain).toHaveLength(2);
    expect(r.log_thought_chain[0].kind).toBe('decision');
    expect(r.log_thought_chain[0].confidence).toBe(0.7);
    expect(r.considered_alternatives.sort()).toEqual(['enum4linux', 'nmap -sV', 'rpcclient']);
    expect(r.prior_actions_referenced.sort()).toEqual(['prior-act-A', 'prior-act-B']);
  });

  it('captures validation + approval state from action_validated events', () => {
    const history = [
      ev({
        event_id: 'v1', timestamp: '2026-01-01T10:00:00Z',
        description: 'queued', event_type: 'action_validated',
        action_id: 'a-2', validation_result: 'valid',
        details: { approval_status: 'approved', auto_approved: true, reason: 'unattended-execute' },
      }),
    ];
    const r = explainAction(history, 'a-2');
    expect(r.validation?.validation_result).toBe('valid');
    expect(r.approval?.approval_status).toBe('approved');
    expect(r.approval?.auto_approved).toBe(true);
    expect(r.approval?.reason).toContain('unattended');
  });

  it('reports the terminal outcome (latest action_completed/action_failed)', () => {
    const history = [
      ev({
        event_id: 's1', timestamp: '2026-01-01T10:00:00Z',
        description: 'started', event_type: 'action_started', action_id: 'a-3',
      }),
      ev({
        event_id: 'f1', timestamp: '2026-01-01T10:00:05Z',
        description: 'failed: timeout', event_type: 'action_failed',
        action_id: 'a-3', result_classification: 'failure',
      }),
    ];
    const r = explainAction(history, 'a-3');
    expect(r.outcome?.classification).toBe('failure');
    expect(r.outcome?.description).toContain('timeout');
  });

  it('drops self-references in prior_actions_referenced', () => {
    const history = [
      ev({
        event_id: 't1', timestamp: '2026-01-01T10:00:00Z',
        description: 'thinking',
        event_type: 'thought', action_id: 'a-self',
        details: { related_action_ids: ['a-self', 'a-other'] },
      }),
    ];
    const r = explainAction(history, 'a-self');
    expect(r.prior_actions_referenced).toEqual(['a-other']);
  });

  it('uses the optional frontierItemLookup to attach a FrontierItem record', () => {
    const history = [
      ev({
        event_id: 'e1', timestamp: '2026-01-01T10:00:00Z',
        description: 'registered', event_type: 'agent_registered',
        action_id: 'a-4', frontier_item_id: 'fi-attach',
      }),
    ];
    const fi: any = {
      id: 'fi-attach', type: 'incomplete_node',
      description: 'enrich host', graph_metrics: {
        hops_to_objective: null, fan_out_estimate: 1, node_degree: 0, confidence: 1,
      },
      opsec_noise: 0.1, staleness_seconds: 0,
    };
    const r = explainAction(history, 'a-4', () => fi);
    expect(r.frontier_item?.id).toBe('fi-attach');
  });
});
