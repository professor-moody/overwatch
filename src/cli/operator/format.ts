// ============================================================
// Operator CLI — terminal formatting (self-contained, no deps)
// ============================================================
// Color auto-disables when stdout is not a TTY (piped) or NO_COLOR is set, and
// can be forced off with setColorEnabled(false) (--no-color). Single style per
// string only — do NOT nest (the reset code clears all attributes).

let colorEnabled = !!process.stdout.isTTY && !process.env.NO_COLOR;

export function setColorEnabled(on: boolean): void { colorEnabled = on; }
export function isColorEnabled(): boolean { return colorEnabled; }

const style = (code: number) => (s: string | number): string =>
  colorEnabled ? `\x1b[${code}m${s}\x1b[0m` : String(s);

export const red = style(31);
export const green = style(32);
export const yellow = style(33);
export const blue = style(34);
export const magenta = style(35);
export const cyan = style(36);
export const gray = style(90);
export const bold = style(1);
export const dim = style(2);

/** Visible length, ignoring ANSI escape sequences (for column alignment). */
export function visibleLength(s: string): number {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '').length;
}

/** Truncate to n visible chars with a trailing ellipsis. Assumes no ANSI in input. */
export function truncate(s: string, n: number): string {
  if (n <= 0) return '';
  return s.length <= n ? s : `${s.slice(0, Math.max(0, n - 1))}…`;
}

const terminalWidth = (): number => (process.stdout.columns && process.stdout.columns > 0 ? process.stdout.columns : 100);

/**
 * Render an aligned text table. `rows` cells are plain (uncolored) strings used
 * for width math; an optional `color` per column tints the cell after sizing so
 * alignment stays correct. The widest column is shrunk to fit the terminal.
 */
export function formatTable(
  headers: string[],
  rows: string[][],
  opts: { color?: Array<((s: string) => string) | undefined> } = {},
): string {
  if (rows.length === 0) return dim('  (none)');
  const cols = headers.length;
  const widths = headers.map((h, c) => Math.max(h.length, ...rows.map(r => (r[c] ?? '').length)));

  // Shrink to terminal width by trimming the widest column.
  const sep = 2;
  const budget = terminalWidth() - sep * (cols - 1);
  let total = widths.reduce((a, b) => a + b, 0);
  while (total > budget && Math.max(...widths) > 6) {
    const widest = widths.indexOf(Math.max(...widths));
    widths[widest] -= 1;
    total -= 1;
  }

  const pad = (s: string, w: number, tint?: (x: string) => string): string => {
    const cell = truncate(s, w);
    const padded = cell + ' '.repeat(Math.max(0, w - cell.length));
    return tint ? tint(padded) : padded;
  };

  const headerLine = headers.map((h, c) => bold(pad(h, widths[c]))).join('  ');
  const body = rows.map(r =>
    r.map((cell, c) => pad(cell ?? '', widths[c], opts.color?.[c])).join('  '),
  );
  return [headerLine, ...body].join('\n');
}

/** Aligned key/value block (for the status command). */
export function keyValues(pairs: Array<[string, string]>): string {
  const keyWidth = Math.max(...pairs.map(([k]) => k.length));
  return pairs.map(([k, v]) => `  ${dim((k + ':').padEnd(keyWidth + 1))} ${v}`).join('\n');
}

/** A section header line. */
export function heading(label: string): string {
  return bold(cyan(label));
}
