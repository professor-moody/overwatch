export function safeCameraDuration(value: unknown, fallback = 300): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}
