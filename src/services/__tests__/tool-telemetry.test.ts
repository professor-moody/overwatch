import { describe, it, expect, beforeEach } from 'vitest';
import { ToolTelemetry } from '../tool-telemetry.js';

describe('ToolTelemetry', () => {
  let telemetry: ToolTelemetry;

  beforeEach(() => {
    telemetry = new ToolTelemetry();
  });

  it('records call counts and timing', () => {
    telemetry.record('get_state', 50, false);
    telemetry.record('get_state', 30, false);
    telemetry.record('next_task', 100, false);

    const stats = telemetry.getStats();
    expect(stats.get('get_state')!.calls).toBe(2);
    expect(stats.get('get_state')!.total_ms).toBe(80);
    expect(stats.get('get_state')!.errors).toBe(0);
    expect(stats.get('next_task')!.calls).toBe(1);
  });

  it('records errors separately', () => {
    telemetry.record('report_finding', 20, false);
    telemetry.record('report_finding', 15, true);
    telemetry.record('report_finding', 10, true);

    const stats = telemetry.getStats();
    expect(stats.get('report_finding')!.calls).toBe(3);
    expect(stats.get('report_finding')!.errors).toBe(2);
  });

  it('detects unused tools', () => {
    telemetry.record('get_state', 50, false);
    telemetry.record('next_task', 30, false);

    const allTools = ['get_state', 'next_task', 'validate_action', 'report_finding'];
    const unused = telemetry.getUnusedTools(allTools);
    expect(unused).toEqual(['validate_action', 'report_finding']);
  });

  it('extracts sequence patterns', () => {
    // Repeat a 3-tool pattern several times
    for (let i = 0; i < 5; i++) {
      telemetry.record('get_state', 10, false);
      telemetry.record('next_task', 10, false);
      telemetry.record('validate_action', 10, false);
    }

    const patterns = telemetry.getSequencePatterns();
    expect(patterns.length).toBeGreaterThan(0);
    const mainPattern = patterns.find(p =>
      p.sequence[0] === 'get_state' && p.sequence[1] === 'next_task' && p.sequence[2] === 'validate_action'
    );
    expect(mainPattern).toBeDefined();
    expect(mainPattern!.count).toBeGreaterThanOrEqual(4);
  });

  it('caps call sequence at max length', () => {
    for (let i = 0; i < 250; i++) {
      telemetry.record(`tool_${i}`, 1, false);
    }
    expect(telemetry.getCallSequence().length).toBeLessThanOrEqual(200);
  });

  it('produces a full summary', () => {
    telemetry.record('get_state', 50, false);
    telemetry.record('get_state', 30, false);
    telemetry.record('next_task', 100, true);

    const allTools = ['get_state', 'next_task', 'validate_action'];
    const summary = telemetry.summarize(allTools);

    expect(summary.total_calls).toBe(3);
    expect(summary.total_errors).toBe(1);
    expect(summary.unused_tools).toEqual(['validate_action']);
    expect(summary.top_tools.length).toBe(2);
    expect(summary.top_tools[0].name).toBe('get_state');
    expect(summary.top_tools[0].avg_ms).toBe(40);
    expect(summary.top_tools[1].error_rate).toBe(1.0);
  });

  it('sets last_called_at timestamp', () => {
    telemetry.record('get_state', 50, false);
    const stats = telemetry.getStats();
    expect(stats.get('get_state')!.last_called_at).toBeDefined();
    expect(new Date(stats.get('get_state')!.last_called_at!).getTime()).toBeGreaterThan(0);
  });
});
