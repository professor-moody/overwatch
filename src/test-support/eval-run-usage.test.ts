import { describe, expect, it } from 'vitest';
import { buildEvalClaudeArgs, parseEvalUsage } from './eval-run.js';

describe('buildEvalClaudeArgs', () => {
  it('passes the model and exact in-flight dollar cap to Claude', () => {
    expect(buildEvalClaudeArgs('claude-sonnet-4-5', 0.25)).toEqual([
      '--model', 'claude-sonnet-4-5',
      '--max-budget-usd', '0.25',
    ]);
  });

  it('does not invent optional arguments for deterministic fake runs', () => {
    expect(buildEvalClaudeArgs()).toEqual([]);
  });
});

describe('parseEvalUsage', () => {
  it('prefers cumulative result usage and reports cache categories separately', () => {
    const ndjson = [
      JSON.stringify({ type: 'assistant', message: { usage: { input_tokens: 2, output_tokens: 3 } } }),
      JSON.stringify({
        type: 'result',
        usage: {
          input_tokens: 5,
          output_tokens: 7,
          cache_read_input_tokens: 11,
          cache_creation_input_tokens: 13,
        },
        total_cost_usd: 0.125,
      }),
    ].join('\n');

    expect(parseEvalUsage(ndjson)).toEqual({
      usage: {
        inputTokens: 5,
        outputTokens: 7,
        cacheReadInputTokens: 11,
        cacheCreationInputTokens: 13,
        accountingTokens: 36,
      },
      costUsd: 0.125,
    });
  });

  it('sums per-turn usage when no cumulative result event exists', () => {
    const ndjson = [
      JSON.stringify({ type: 'assistant', message: { usage: { input_tokens: 2, output_tokens: 3, cache_read_input_tokens: 5 } } }),
      JSON.stringify({ type: 'assistant', message: { usage: { input_tokens: 7, output_tokens: 11, cache_creation_input_tokens: 13 } } }),
    ].join('\n');

    expect(parseEvalUsage(ndjson).usage).toEqual({
      inputTokens: 9,
      outputTokens: 14,
      cacheReadInputTokens: 5,
      cacheCreationInputTokens: 13,
      accountingTokens: 41,
    });
  });
});
