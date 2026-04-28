// ============================================================
// Overwatch — Tool Call Telemetry
// Runtime-only instrumentation for tool usage analysis.
// Not persisted — exported via retrospective.
// ============================================================

export interface ToolStats {
  calls: number;
  errors: number;
  total_ms: number;
  last_called_at?: string;
}

export interface SequencePattern {
  sequence: string[];
  count: number;
}

export interface TelemetrySummary {
  tool_stats: Record<string, ToolStats>;
  total_calls: number;
  total_errors: number;
  unused_tools: string[];
  top_tools: Array<{ name: string; calls: number; avg_ms: number; error_rate: number }>;
  common_sequences: SequencePattern[];
}

const MAX_SEQUENCE_LENGTH = 200;
const SEQUENCE_WINDOW = 3; // trigram patterns

export class ToolTelemetry {
  private stats = new Map<string, ToolStats>();
  private callSequence: string[] = [];

  record(tool: string, duration_ms: number, error: boolean): void {
    const existing = this.stats.get(tool) || { calls: 0, errors: 0, total_ms: 0 };
    existing.calls++;
    existing.total_ms += duration_ms;
    if (error) existing.errors++;
    existing.last_called_at = new Date().toISOString();
    this.stats.set(tool, existing);

    this.callSequence.push(tool);
    if (this.callSequence.length > MAX_SEQUENCE_LENGTH) {
      this.callSequence = this.callSequence.slice(-MAX_SEQUENCE_LENGTH);
    }
  }

  getStats(): Map<string, ToolStats> {
    return new Map(this.stats);
  }

  getUnusedTools(allToolNames: string[]): string[] {
    return allToolNames.filter(name => !this.stats.has(name));
  }

  getSequencePatterns(topN: number = 5): SequencePattern[] {
    if (this.callSequence.length < SEQUENCE_WINDOW) return [];

    const counts = new Map<string, number>();
    for (let i = 0; i <= this.callSequence.length - SEQUENCE_WINDOW; i++) {
      const key = this.callSequence.slice(i, i + SEQUENCE_WINDOW).join(' → ');
      counts.set(key, (counts.get(key) || 0) + 1);
    }

    return Array.from(counts.entries())
      .filter(([, count]) => count >= 2)
      .sort(([, a], [, b]) => b - a)
      .slice(0, topN)
      .map(([key, count]) => ({ sequence: key.split(' → '), count }));
  }

  summarize(allToolNames: string[]): TelemetrySummary {
    let totalCalls = 0;
    let totalErrors = 0;
    const toolStats: Record<string, ToolStats> = {};

    for (const [name, stats] of this.stats) {
      toolStats[name] = { ...stats };
      totalCalls += stats.calls;
      totalErrors += stats.errors;
    }

    const topTools = Array.from(this.stats.entries())
      .sort(([, a], [, b]) => b.calls - a.calls)
      .slice(0, 10)
      .map(([name, s]) => ({
        name,
        calls: s.calls,
        avg_ms: s.calls > 0 ? Math.round(s.total_ms / s.calls) : 0,
        error_rate: s.calls > 0 ? s.errors / s.calls : 0,
      }));

    return {
      tool_stats: toolStats,
      total_calls: totalCalls,
      total_errors: totalErrors,
      unused_tools: this.getUnusedTools(allToolNames),
      top_tools: topTools,
      common_sequences: this.getSequencePatterns(),
    };
  }

  getCallSequence(): string[] {
    return [...this.callSequence];
  }
}
