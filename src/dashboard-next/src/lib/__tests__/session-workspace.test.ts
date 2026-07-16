import { describe, expect, it } from 'vitest';
import {
  addAttachedSession,
  cleanTerminalText,
  extractCommandLikeLines,
  groupForSession,
  groupSessions,
  relatedSessionActions,
  relatedSessionActivity,
  relatedSessionFrontier,
  removeAttachedSession,
  searchSession,
  searchSessionBuffer,
  sessionBufferRequestKey,
  sessionCopyFields,
  sessionsForAgent,
  sessionSupportsResize,
  sortSessionsForWorkspace,
} from '../session-workspace';
import type { ActivityEntry, FrontierItem, PendingAction, SessionInfo } from '../types';

const session = (props: Partial<SessionInfo>): SessionInfo => ({
  id: 'session-1',
  kind: 'pty',
  state: 'connected',
  title: 'Shell',
  ...props,
});

const action = (props: Partial<PendingAction>): PendingAction => ({
  action_id: 'act-1',
  technique: 'test',
  target: 'host-a',
  noise_level: 0.1,
  description: 'test action',
  submitted_at: '2026-05-15T00:00:00Z',
  ...props,
});

const frontier = (props: Record<string, unknown> = {}): FrontierItem => ({
  id: 'fi-1',
  type: 'incomplete_node',
  node_id: 'host-a',
  description: 'frontier',
  graph_metrics: { hops_to_objective: 1, fan_out_estimate: 1, node_degree: 1, confidence: 1 },
  opsec_noise: 0.2,
  staleness_seconds: 0,
  ...props,
} as FrontierItem);

const activity = (props: Partial<ActivityEntry>): ActivityEntry => ({
  id: 'evt-1',
  timestamp: '2026-05-15T00:00:00Z',
  event_type: 'action_started',
  description: 'started',
  ...props,
});

describe('session workspace helpers', () => {
  it('groups sessions by operator state', () => {
    const grouped = groupSessions([
      session({ id: 'live', state: 'connected' }),
      session({ id: 'pending', state: 'pending' }),
      session({ id: 'resume', state: 'resume_available' }),
      session({ id: 'interrupted', state: 'interrupted' }),
      session({ id: 'closed', state: 'closed' }),
      session({ id: 'error', state: 'error' }),
    ]);

    expect(grouped.live.map(s => s.id)).toEqual(['live']);
    expect(grouped.pending.map(s => s.id)).toEqual(['pending']);
    expect(grouped.resume_available.map(s => s.id)).toEqual(['resume']);
    expect(grouped.interrupted.map(s => s.id)).toEqual(['interrupted']);
    expect(grouped.error.map(s => s.id)).toEqual(['error']);
    expect(grouped.closed.map(s => s.id)).toEqual(['closed']);
  });

  it('filters by target, owner, notes, and identifiers', () => {
    const s = session({
      id: 'session-alpha',
      target_node: 'host-dc01',
      credential_node: 'cred-1',
      claimed_by: 'agent-7',
      notes: 'interesting shell',
    });

    expect(searchSession(s, 'dc01')).toBe(true);
    expect(searchSession(s, 'agent-7')).toBe(true);
    expect(searchSession(s, 'interesting')).toBe(true);
    expect(searchSession(s, 'missing')).toBe(false);
  });

  it('sorts live before pending before closed and newest first inside groups', () => {
    const sorted = sortSessionsForWorkspace([
      session({ id: 'old-live', state: 'connected', last_activity_at: '2026-05-15T00:00:00Z' }),
      session({ id: 'closed', state: 'closed', last_activity_at: '2026-05-15T02:00:00Z' }),
      session({ id: 'new-live', state: 'connected', last_activity_at: '2026-05-15T03:00:00Z' }),
      session({ id: 'pending', state: 'pending', last_activity_at: '2026-05-15T04:00:00Z' }),
    ]);

    expect(sorted.map(s => s.id)).toEqual(['new-live', 'old-live', 'pending', 'closed']);
  });

  it('updates attached terminal id state without duplicates', () => {
    expect(addAttachedSession(['a'], 'a')).toEqual(['a']);
    expect(addAttachedSession(['a'], 'b')).toEqual(['a', 'b']);
    expect(removeAttachedSession(['a', 'b'], 'a')).toEqual(['b']);
  });

  it('changes the buffer request key across connection generations and lifecycle transitions', () => {
    const generationOne = session({
      id: 'listener-1',
      state: 'connected',
      connection_id: 'listener-1:g1',
      connection_generation: 1,
    });
    const generationTwo = session({
      ...generationOne,
      connection_id: 'listener-1:g2',
      connection_generation: 2,
    });
    const disconnected = session({
      ...generationTwo,
      state: 'pending',
      connection_id: undefined,
      last_connection_id: 'listener-1:g2',
    });

    expect(sessionBufferRequestKey(generationOne)).not.toBe(
      sessionBufferRequestKey(generationTwo),
    );
    expect(sessionBufferRequestKey(generationTwo)).not.toBe(
      sessionBufferRequestKey(disconnected),
    );
  });

  it('only treats sessions with explicit resize support as terminal-resizable', () => {
    expect(sessionSupportsResize(session({ capabilities: { supports_resize: true } }))).toBe(true);
    expect(sessionSupportsResize(session({ kind: 'socket', capabilities: { supports_resize: false, tty_quality: 'dumb' } }))).toBe(false);
    expect(sessionSupportsResize(session({ capabilities: undefined }))).toBe(false);
  });

  it('extracts related actions, frontier items, activity, and copy fields', () => {
    const s = session({
      id: 'sess-1',
      action_id: 'act-1',
      frontier_item_id: 'fi-1',
      target_node: 'host-a',
    });

    expect(relatedSessionActions(s, [
      action({ action_id: 'act-1' }),
      action({ action_id: 'act-2', target: 'host-z', target_node: 'host-z' }),
    ]).map(item => item.action_id)).toEqual(['act-1']);

    expect(relatedSessionFrontier(s, [
      frontier({ id: 'fi-1' }),
      frontier({ id: 'fi-2', node_id: 'host-z' }),
    ]).map(item => item.id)).toEqual(['fi-1']);

    expect(relatedSessionActivity(s, [
      activity({ action_id: 'act-1' }),
      activity({ id: 'evt-2', details: { session_id: 'sess-1' } }),
      activity({ id: 'evt-3', action_id: 'act-x' }),
    ]).map(item => item.id)).toEqual(['evt-1', 'evt-2']);

    expect(sessionCopyFields(s).map(field => field.label)).toEqual(['Session', 'Action', 'Frontier', 'Target']);
  });

  it('cleans, searches, and extracts command-like terminal buffer lines', () => {
    const buffer = {
      session_id: 'sess-1',
      start_pos: 0,
      end_pos: 96,
      truncated: true,
      text: '\u001b[32mConnected\u001b[0m\r\ncorp\\jdoe@WS01 C:\\Users\\jdoe> whoami\r\ncorp\\jdoe\r\n$ hostname\r\nWS01\r\n',
    };

    expect(cleanTerminalText(buffer.text)).not.toContain('\u001b');
    expect(extractCommandLikeLines(buffer).map(command => command.text)).toEqual(['whoami', 'hostname']);
    expect(searchSessionBuffer(buffer, 'jdoe').map(match => match.line)).toEqual([2, 3]);
  });

  it('finds sessions by canonical task ownership without guessing from labels', () => {
    const sessions = [
      session({ id: 'by-task', agent_id: 'task-123' }),
      session({ id: 'by-label', agent_id: 'recon-1' }),
      session({ id: 'by-claim', claimed_by: 'task-123', agent_id: 'recon-1' }),
      session({ id: 'other', agent_id: 'task-999' }),
      session({ id: 'unowned' }),
    ];
    const matched = sessionsForAgent(sessions, {
      task_id: 'task-123',
      id: 'task-123',
      agent_id: 'recon-1',
    });
    expect(matched.map(s => s.id).sort()).toEqual(['by-claim', 'by-task']);
  });

  it('returns no sessions for a null agent or an agent with no identifiers', () => {
    const sessions = [session({ id: 'a', agent_id: 'task-1' })];
    expect(sessionsForAgent(sessions, null)).toEqual([]);
    expect(sessionsForAgent(sessions, {})).toEqual([]);
    expect(sessionsForAgent([], { id: 'task-1' })).toEqual([]);
  });

  it('splits error sessions out from closed into their own group', () => {
    expect(groupForSession(session({ state: 'connected' }))).toBe('live');
    expect(groupForSession(session({ state: 'pending' }))).toBe('pending');
    expect(groupForSession(session({ state: 'resume_available' }))).toBe('resume_available');
    expect(groupForSession(session({ state: 'interrupted' }))).toBe('interrupted');
    expect(groupForSession(session({ state: 'error' }))).toBe('error');
    expect(groupForSession(session({ state: 'closed' }))).toBe('closed');

    const grouped = groupSessions([
      session({ id: 'l', state: 'connected' }),
      session({ id: 'e', state: 'error' }),
      session({ id: 'c', state: 'closed' }),
    ]);
    expect(grouped.error.map(s => s.id)).toEqual(['e']);
    expect(grouped.closed.map(s => s.id)).toEqual(['c']);
  });

  it('orders error above closed (errors are more actionable than clean teardowns)', () => {
    const sorted = sortSessionsForWorkspace([
      session({ id: 'c', state: 'closed' }),
      session({ id: 'e', state: 'error' }),
      session({ id: 'l', state: 'connected' }),
    ]);
    expect(sorted.map(s => s.id)).toEqual(['l', 'e', 'c']);
  });
});
