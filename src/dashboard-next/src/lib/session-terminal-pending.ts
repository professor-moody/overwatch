import type { SessionWebSocketClientEvent } from '@overwatch/dashboard-contracts';

export interface TerminalMutationGeneration {
  session_id: string;
  connection_id: string;
  connection_generation: number;
}

const pendingByGeneration = new Map<
  string,
  Map<string, SessionWebSocketClientEvent>
>();
const generationByKey = new Map<string, TerminalMutationGeneration>();

export function terminalMutationGenerationKey(
  generation: TerminalMutationGeneration,
): string {
  return JSON.stringify([
    generation.session_id,
    generation.connection_id,
    generation.connection_generation,
  ]);
}

/** Page-lifetime, memory-only ownership for ambiguous terminal writes. Never
 * persist these payloads: interactive input may contain credentials. */
export function pendingTerminalMutationBucket(
  generation: TerminalMutationGeneration,
): Map<string, SessionWebSocketClientEvent> {
  const key = terminalMutationGenerationKey(generation);
  let bucket = pendingByGeneration.get(key);
  if (!bucket) {
    bucket = new Map();
    pendingByGeneration.set(key, bucket);
    generationByKey.set(key, { ...generation });
  }
  return bucket;
}

export function settlePendingTerminalMutation(
  generation: TerminalMutationGeneration,
  commandId: string,
  status: 'accepted' | 'running' | 'succeeded' | 'failed' | 'interrupted',
): boolean {
  if (status === 'accepted' || status === 'running') return false;
  const key = terminalMutationGenerationKey(generation);
  const bucket = pendingByGeneration.get(key);
  if (!bucket) return false;
  const removed = bucket.delete(commandId);
  if (bucket.size === 0) {
    pendingByGeneration.delete(key);
    generationByKey.delete(key);
  }
  return removed;
}

export function listPendingTerminalMutations(): Array<{
  generation: TerminalMutationGeneration;
  command: SessionWebSocketClientEvent;
}> {
  const result: Array<{
    generation: TerminalMutationGeneration;
    command: SessionWebSocketClientEvent;
  }> = [];
  for (const [key, bucket] of pendingByGeneration) {
    const generation = generationByKey.get(key);
    if (!generation) continue;
    for (const command of bucket.values()) {
      result.push({ generation: { ...generation }, command: { ...command } });
    }
  }
  return result;
}

export function resetPendingTerminalMutationsForTest(): void {
  pendingByGeneration.clear();
  generationByKey.clear();
}
