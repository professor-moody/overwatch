/** Browser-safe atomic keyed-collection patch shared by the dashboard protocol
 * producer tests and the real client store. Move indices are final positions,
 * not sequential splice instructions. */
export interface AtomicIndexedCollectionPatch<T> {
  upsert: T[];
  remove: string[];
  moves: Array<{ id: string; index: number }>;
  total: number;
  replace?: T[];
}

export function applyIndexedCollectionPatch<T>(
  current: readonly T[],
  patch: AtomicIndexedCollectionPatch<T>,
  idOf: (value: T) => string,
): T[] {
  if (patch.replace) return structuredClone(patch.replace);
  const removed = new Set(patch.remove);
  const upsert = new Map(patch.upsert.map(value => [idOf(value), value]));
  const currentById = new Map<string, T>();
  for (const value of current) {
    const id = idOf(value);
    if (!id || currentById.has(id)) {
      throw new Error(`Dashboard collection contains an empty or duplicate canonical id: ${id || '<empty>'}.`);
    }
    currentById.set(id, value);
  }
  const moveIds = new Set(patch.moves.map(move => move.id));
  const stationary: T[] = [];
  for (const [id, value] of currentById) {
    if (removed.has(id) || moveIds.has(id)) continue;
    stationary.push(upsert.get(id) ?? value);
  }

  const values = new Array<T | undefined>(patch.total);
  for (const move of patch.moves) {
    const value = upsert.get(move.id) ?? currentById.get(move.id);
    if (value === undefined) {
      throw new Error(`Dashboard collection move references missing id ${move.id}.`);
    }
    if (move.index >= patch.total || values[move.index] !== undefined) {
      throw new Error(`Dashboard collection move has invalid or duplicate index ${move.index}.`);
    }
    values[move.index] = value;
  }

  let stationaryIndex = 0;
  for (let index = 0; index < values.length; index++) {
    if (values[index] !== undefined) continue;
    values[index] = stationary[stationaryIndex++];
  }
  if (stationaryIndex !== stationary.length || values.some(value => value === undefined)) {
    throw new Error(`Dashboard collection patch could not produce exactly ${patch.total} records.`);
  }
  const result = values as T[];
  const resultIds = new Set(result.map(idOf));
  if (
    resultIds.size !== patch.total
    || [...upsert.keys()].some(id => !resultIds.has(id))
    || [...removed].some(id => resultIds.has(id))
  ) {
    throw new Error('Dashboard collection patch did not converge to its declared canonical IDs.');
  }
  return result;
}
