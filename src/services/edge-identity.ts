import { createHash } from 'crypto';
import type { EdgeProperties } from '../types.js';

export function isScopeAwareEdgeType(type: string): boolean {
  return type === 'HAS_POLICY' || type === 'POLICY_ALLOWS';
}

export function edgeScope(props: EdgeProperties | Partial<EdgeProperties>): string | undefined {
  if (!isScopeAwareEdgeType(String(props.type ?? ''))) return undefined;
  const scope = (props as unknown as { scope?: unknown }).scope;
  return typeof scope === 'string' && scope.length > 0 ? scope : undefined;
}

export function edgeIdentityMatches(
  existing: EdgeProperties,
  incoming: EdgeProperties,
): boolean {
  return existing.type === incoming.type
    && edgeScope(existing) === edgeScope(incoming);
}

/** Preserve the existing human-readable key format for ordinary edges. */
export function preferredEdgeKey(
  source: string,
  target: string,
  props: EdgeProperties,
): string {
  const baseKey = `${source}--${props.type}--${target}`;
  const scope = edgeScope(props);
  return scope === undefined
    ? baseKey
    : `${baseKey}--${createHash('sha1').update(scope).digest('hex').slice(0, 10)}`;
}

/** A graph-wide preferred key can collide when node IDs contain the delimiter.
 * Derive the fallback from the unambiguous tuple so crash replay chooses the
 * same identity instead of generating a new random suffix. */
export function deterministicCollisionEdgeKey(
  source: string,
  target: string,
  props: EdgeProperties,
): string {
  const preferred = preferredEdgeKey(source, target, props);
  const identity = JSON.stringify([source, props.type, target, edgeScope(props) ?? null]);
  const digest = createHash('sha256').update(identity).digest('hex').slice(0, 16);
  return `${preferred}--collision-${digest}`;
}
