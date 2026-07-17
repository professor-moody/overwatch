export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): unknown;
  removeItem(key: string): unknown;
  clear?(): unknown;
}

export interface SafeBrowserStorage extends StorageLike {
  setItem(key: string, value: string): boolean;
  removeItem(key: string): boolean;
}

export type BrowserStorageArea = 'local' | 'session';

const localMemory = new Map<string, string>();
const sessionMemory = new Map<string, string>();

export function resetBrowserStorageMemoryForTest(): void {
  localMemory.clear();
  sessionMemory.clear();
  try { resolveBrowserStorage('local')?.clear?.(); } catch { /* synthetic storage may be disabled */ }
  try { resolveBrowserStorage('session')?.clear?.(); } catch { /* synthetic storage may be disabled */ }
}

function resolveBrowserStorage(area: BrowserStorageArea): StorageLike | undefined {
  if (typeof window === 'undefined') return undefined;
  try {
    return area === 'local' ? window.localStorage : window.sessionStorage;
  } catch {
    return undefined;
  }
}

/**
 * Wrap browser storage behind a no-throw, page-lifetime memory fallback.
 * Persistent storage is an optimization only: React state, durable server
 * state, and the in-memory graph remain authoritative when a browser policy
 * denies property access or individual storage methods.
 */
export function createSafeBrowserStorage(
  area: BrowserStorageArea,
  resolveStorage: () => StorageLike | undefined = () => resolveBrowserStorage(area),
  memory: Map<string, string> = area === 'local' ? localMemory : sessionMemory,
  memoryFallback = true,
): SafeBrowserStorage {
  const volatileKeys = new Set<string>();
  return {
    getItem(key: string): string | null {
      if (volatileKeys.has(key)) return memoryFallback ? memory.get(key) ?? null : null;
      try {
        const storage = resolveStorage();
        if (storage) {
          const persisted = storage.getItem(key);
          if (persisted === null || persisted === undefined) {
            memory.delete(key);
            return null;
          }
          memory.set(key, persisted);
          return persisted;
        }
      } catch {
        // Fall through to the page-lifetime copy.
      }
      return memoryFallback ? memory.get(key) ?? null : null;
    },
    setItem(key: string, value: string): boolean {
      if (memoryFallback) memory.set(key, value);
      try {
        const storage = resolveStorage();
        if (!storage) {
          if (memoryFallback) volatileKeys.add(key);
          return false;
        }
        storage.setItem(key, value);
        volatileKeys.delete(key);
        return true;
      } catch {
        if (memoryFallback) volatileKeys.add(key);
        return false;
      }
    },
    removeItem(key: string): boolean {
      memory.delete(key);
      try {
        const storage = resolveStorage();
        if (!storage) {
          if (memoryFallback) volatileKeys.add(key);
          return false;
        }
        storage.removeItem(key);
        volatileKeys.delete(key);
        return true;
      } catch {
        if (memoryFallback) volatileKeys.add(key);
        return false;
      }
    },
  };
}

const browserPageLifetime = typeof window !== 'undefined';
export const safeLocalStorage = createSafeBrowserStorage(
  'local',
  undefined,
  localMemory,
  browserPageLifetime,
);
export const safeSessionStorage = createSafeBrowserStorage(
  'session',
  undefined,
  sessionMemory,
  browserPageLifetime,
);
