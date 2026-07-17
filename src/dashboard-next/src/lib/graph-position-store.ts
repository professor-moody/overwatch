import {
  createSafeBrowserStorage,
  safeLocalStorage,
  type StorageLike,
} from './browser-storage';

export interface GraphNodePosition {
  x: number;
  y: number;
}

type PositionMap = Record<string, GraphNodePosition>;

const PREFIX = 'overwatch:graph-positions';
const injectedStorageAdapters = new WeakMap<StorageLike, StorageLike>();

export function graphPositionStorageKey(engagementId: string | undefined | null): string {
  return `${PREFIX}:${engagementId || 'default'}`;
}

function getStorage(storage?: StorageLike): StorageLike {
  if (!storage) return safeLocalStorage;
  let adapter = injectedStorageAdapters.get(storage);
  if (!adapter) {
    adapter = createSafeBrowserStorage('local', () => storage, new Map());
    injectedStorageAdapters.set(storage, adapter);
  }
  return adapter;
}

function validPosition(value: unknown): value is GraphNodePosition {
  if (!value || typeof value !== 'object') return false;
  const p = value as GraphNodePosition;
  return Number.isFinite(p.x) && Number.isFinite(p.y);
}

function readGraphPositions(
  engagementId: string | undefined | null,
  target: StorageLike,
): PositionMap {
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

export function loadGraphPositions(
  engagementId: string | undefined | null,
  storage?: StorageLike,
): PositionMap {
  const target = getStorage(storage);
  return readGraphPositions(engagementId, target);
}

export function saveGraphNodePosition(
  engagementId: string | undefined | null,
  nodeId: string,
  position: GraphNodePosition,
  storage?: StorageLike,
): PositionMap {
  const target = getStorage(storage);
  const current = readGraphPositions(engagementId, target);
  current[nodeId] = position;
  target.setItem(graphPositionStorageKey(engagementId), JSON.stringify(current));
  return current;
}

export function clearGraphPositions(
  engagementId: string | undefined | null,
  storage?: StorageLike,
): void {
  const target = getStorage(storage);
  target.removeItem(graphPositionStorageKey(engagementId));
}
