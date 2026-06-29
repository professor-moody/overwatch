import { describe, it, expect } from 'vitest';
import { toolText } from '../_tool-output.js';

describe('toolText', () => {
  const value = { a: 1, nested: { b: [1, 2, 3] }, s: 'x' };

  it('pretty-prints by default (2-space indentation) — unchanged behavior', () => {
    const { content } = toolText(value);
    expect(content[0].type).toBe('text');
    expect(content[0].text).toBe(JSON.stringify(value, null, 2));
    expect(content[0].text).toContain('\n  '); // indented
  });

  it('compact mode emits no indentation but round-trips identically', () => {
    const { content } = toolText(value, { compact: true });
    expect(content[0].text).toBe(JSON.stringify(value));
    expect(content[0].text).not.toContain('\n  ');
    expect(JSON.parse(content[0].text)).toEqual(value); // same payload, only whitespace differs
  });

  it('compact:false is byte-identical to the default', () => {
    expect(toolText(value, { compact: false }).text ?? toolText(value, { compact: false }).content[0].text)
      .toBe(toolText(value).content[0].text);
  });
});
