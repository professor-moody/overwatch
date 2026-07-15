/**
 * Decode durable JSON bytes without Unicode replacement.
 *
 * Buffer.toString('utf-8') replaces malformed byte sequences with U+FFFD.
 * That is convenient for display text but unsafe for persistence: corrupt
 * bytes could otherwise become different, apparently valid JSON and later be
 * checkpointed over. Keep BOM handling aligned with Buffer.toString so a BOM
 * remains visible to JSON.parse rather than being silently stripped.
 */
export function decodeUtf8Fatal(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', {
    fatal: true,
    ignoreBOM: true,
  }).decode(bytes);
}

export function parseJsonBytes(bytes: Uint8Array): unknown {
  return JSON.parse(decodeUtf8Fatal(bytes)) as unknown;
}
