export interface GraphNodePosition {
  x: number;
  y: number;
}

type PositionMap = Record<string, GraphNodePosition>;

interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

const PREFIX = 'overwatch:graph-positions';

export function graphPositionStorageKey(engagementId: string | undefined | null): string {
  return `${PREFIX}:${engagementId || 'default'}`;
}

function getStorage(storage?: StorageLike): StorageLike | null {
  if (storage) return storage;
  if (typeof window === 'undefined') return null;
  return window.localStorage;
}

function validPosition(value: unknown): value is GraphNodePosition {
  if (!value || typeof value !== 'object') return false;
  const p = value as GraphNodePosition;
  return Number.isFinite(p.x) && Number.isFinite(p.y);
}

export function loadGraphPositions(
  engagementId: string | undefined | null,
  storage?: StorageLike,
): PositionMap {
  const target = getStorage(storage);
  if (!target) return {};
  const raw = target.getItem(graphPositionStorageKey(engagementId));
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const positions: PositionMap = {};
    for (const [nodeId, pos] of Object.entries(parsed)) {
      if (validPosition(pos)) positions[nodeId] = { x: pos.x, y: pos.y };
    }
    return positions;
  } catch {
    return {};
  }
}

export function saveGraphNodePosition(
  engagementId: string | undefined | null,
  nodeId: string,
  position: GraphNodePosition,
  storage?: StorageLike,
): PositionMap {
  const target = getStorage(storage);
  const current = loadGraphPositions(engagementId, target || undefined);
  current[nodeId] = position;
  if (target) target.setItem(graphPositionStorageKey(engagementId), JSON.stringify(current));
  return current;
}

export function clearGraphPositions(
  engagementId: string | undefined | null,
  storage?: StorageLike,
): void {
  const target = getStorage(storage);
  target?.removeItem(graphPositionStorageKey(engagementId));
}
