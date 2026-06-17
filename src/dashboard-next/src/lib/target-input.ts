import type { ScopeConfig } from './types';

// Phase 4c — parse a pasted target blob for the Add Targets modal.
//
// The classification rules below are copied VERBATIM from the command
// interpreter (src/services/command-interpreter.ts:43-45, 101-109) so the
// dashboard accepts exactly what the "scan …" command bar accepts — same
// regexes, same tokenizer, same first-match order, same IP→/32 folding, same
// IPv6-rejected-by-exclusion behavior. If those server rules change, change
// these too. (Dedupe + cap below are dashboard-only UX guards; they don't
// affect classification, and the server re-derives deltas on confirm, so they
// can't make the dashboard diverge from the command bar's scope outcome.)
const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i;

// Guard against a paste-bomb. The command bar has no cap, but a textarea does;
// 256 valid entries is far above any realistic mid-engagement add.
const MAX_ENTRIES = 256;

export interface ParsedTargets {
  /** CIDR tokens plus bare IPs folded to /32 (matches the command bar). */
  cidrs: string[];
  /** Domains, lowercased. */
  domains: string[];
  /** Tokens that matched nothing — including IPv6, which is unsupported. */
  invalid: string[];
  /** True when the valid-entry cap was hit and later entries were dropped. */
  truncated: boolean;
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

/**
 * Tokenize on whitespace/commas and classify each token: CIDR → bare IP (→/32)
 * → domain (lowercased) → invalid, first match wins. Output buckets are deduped
 * and capped; `truncated` flags when the cap dropped valid entries.
 */
export function parseTargetBlob(blob: string): ParsedTargets {
  const tokens = blob.split(/[\s,]+/).filter(Boolean);
  const cidrs: string[] = [];
  const domains: string[] = [];
  const invalid: string[] = [];

  for (const tok of tokens) {
    if (CIDR_RE.test(tok)) cidrs.push(tok);
    else if (IP_RE.test(tok)) cidrs.push(`${tok}/32`);
    else if (DOMAIN_RE.test(tok)) domains.push(tok.toLowerCase());
    else invalid.push(tok);
  }

  const dedupedCidrs = dedupe(cidrs);
  const dedupedDomains = dedupe(domains);
  const truncated = dedupedCidrs.length + dedupedDomains.length > MAX_ENTRIES;

  // Cap the combined valid set, CIDRs first, so a huge paste can't lock the UI.
  const cappedCidrs = dedupedCidrs.slice(0, MAX_ENTRIES);
  const cappedDomains = dedupedDomains.slice(0, Math.max(0, MAX_ENTRIES - cappedCidrs.length));

  return {
    cidrs: cappedCidrs,
    domains: cappedDomains,
    invalid: dedupe(invalid),
    truncated,
  };
}

/**
 * Merge parsed targets into the current scope, producing the full-replacement
 * body the PATCH/preview endpoints expect (they diff it against current scope
 * to derive add/remove deltas). Existing entries are preserved; new cidrs and
 * domains are unioned in (deduped, order-stable: existing first). Other scope
 * fields (exclusions, hosts, …) are passed through untouched.
 */
export function mergeScopeWithTargets(
  current: ScopeConfig | undefined,
  parsed: ParsedTargets,
): ScopeConfig {
  const base = current ?? {};
  return {
    ...base,
    cidrs: dedupe([...(base.cidrs ?? []), ...parsed.cidrs]),
    domains: dedupe([...(base.domains ?? []), ...parsed.domains]),
  };
}

/** Whether a parsed blob has anything worth previewing/confirming. */
export function hasParsedTargets(parsed: ParsedTargets): boolean {
  return parsed.cidrs.length > 0 || parsed.domains.length > 0;
}
