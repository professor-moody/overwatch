// ============================================================
// AWS IAM trust / resource policy normalization helpers.
//
// All AWS IAM-style documents allow `Statement` to be either a single
// statement object or an array of statements. Several parsers (cloud.ts /
// pacu, scoutsuite.ts, terraform.ts) historically only handled the array
// form, silently dropping the single-statement variant. This module
// centralizes:
//   - Statement normalization (single object → [single object])
//   - Trust-principal extraction across Principal.AWS / Service /
//     Federated / CanonicalUser / "*" forms
//   - Condition extraction (ExternalId, MFA, SourceArn, SourceAccount, ...)
//   - A single iterator that yields one normalized trust grant per
//     (statement, principal) pair so callers can emit edges uniformly.
// ============================================================

export interface AwsTrustCondition {
  external_id_required?: string | string[];
  mfa_required?: boolean;
  source_arn_restriction?: string | string[];
  source_account_restriction?: string | string[];
  /** Raw Condition block, kept as-is for downstream auditing. */
  raw_condition?: Record<string, unknown>;
}

/** Kind of trusted principal in an AWS trust policy. */
export type AwsPrincipalKind =
  | 'aws'           // Principal.AWS — IAM user/role/account ARN
  | 'service'       // Principal.Service — e.g. lambda.amazonaws.com
  | 'federated'     // Principal.Federated — SAML/OIDC provider
  | 'canonical'     // Principal.CanonicalUser
  | 'wildcard';     // Principal: "*"

export interface AwsTrustGrant {
  principal: string;
  principal_kind: AwsPrincipalKind;
  effect: 'Allow' | 'Deny';
  action?: string | string[];
  conditions?: AwsTrustCondition;
  /** True when the trust grant carries any Condition entries. */
  conditional: boolean;
}

/** Normalize Statement → array. Handles undefined, single object, or array. */
export function normalizeStatements(doc: unknown): Array<Record<string, unknown>> {
  if (!doc || typeof doc !== 'object') return [];
  const stmt = (doc as Record<string, unknown>).Statement;
  if (!stmt) return [];
  if (Array.isArray(stmt)) {
    return stmt.filter((s): s is Record<string, unknown> => !!s && typeof s === 'object');
  }
  if (typeof stmt === 'object') return [stmt as Record<string, unknown>];
  return [];
}

function asStringArray(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string');
  return [];
}

/**
 * Extract structured trust conditions from a statement's Condition block.
 * Returns undefined if no Condition is present so callers can distinguish
 * unconditional trust from conditional trust without inspecting an empty
 * object.
 */
export function extractTrustConditions(stmt: Record<string, unknown>): AwsTrustCondition | undefined {
  const cond = stmt.Condition;
  if (!cond || typeof cond !== 'object') return undefined;
  const c = cond as Record<string, Record<string, unknown>>;
  const out: AwsTrustCondition = { raw_condition: cond as Record<string, unknown> };

  // sts:ExternalId can appear under StringEquals / StringEqualsIgnoreCase.
  for (const op of ['StringEquals', 'StringEqualsIgnoreCase', 'StringLike']) {
    const block = c[op];
    if (!block) continue;
    const ext = block['sts:ExternalId'] ?? block['sts:externalid'];
    if (ext !== undefined) {
      const arr = asStringArray(ext);
      if (arr.length === 1) out.external_id_required = arr[0];
      else if (arr.length > 1) out.external_id_required = arr;
    }
    const srcArn = block['aws:SourceArn'] ?? block['AWS:SourceArn'];
    if (srcArn !== undefined) {
      const arr = asStringArray(srcArn);
      if (arr.length === 1) out.source_arn_restriction = arr[0];
      else if (arr.length > 1) out.source_arn_restriction = arr;
    }
    const srcAcc = block['aws:SourceAccount'] ?? block['AWS:SourceAccount'];
    if (srcAcc !== undefined) {
      const arr = asStringArray(srcAcc);
      if (arr.length === 1) out.source_account_restriction = arr[0];
      else if (arr.length > 1) out.source_account_restriction = arr;
    }
  }

  // ArnLike / ArnEquals SourceArn forms.
  for (const op of ['ArnLike', 'ArnEquals']) {
    const block = c[op];
    if (!block) continue;
    const srcArn = block['aws:SourceArn'] ?? block['AWS:SourceArn'];
    if (srcArn !== undefined && out.source_arn_restriction === undefined) {
      const arr = asStringArray(srcArn);
      if (arr.length === 1) out.source_arn_restriction = arr[0];
      else if (arr.length > 1) out.source_arn_restriction = arr;
    }
  }

  // MFA presence (Bool / BoolIfExists with aws:MultiFactorAuthPresent: true).
  for (const op of ['Bool', 'BoolIfExists']) {
    const block = c[op];
    if (!block) continue;
    const mfa = block['aws:MultiFactorAuthPresent'] ?? block['AWS:MultiFactorAuthPresent'];
    if (mfa === true || mfa === 'true' || (Array.isArray(mfa) && mfa.includes('true'))) {
      out.mfa_required = true;
    }
  }

  return out;
}

/**
 * Yield one AwsTrustGrant per (statement, principal). Walks Principal.AWS,
 * Principal.Service, Principal.Federated, Principal.CanonicalUser, and the
 * `Principal: "*"` wildcard. Callers can filter on grant.principal_kind to
 * pick the form they want to materialize as an edge.
 */
export function* iterateTrustGrants(doc: unknown): Generator<AwsTrustGrant> {
  for (const stmt of normalizeStatements(doc)) {
    const effectRaw = stmt.Effect;
    const effect: 'Allow' | 'Deny' = effectRaw === 'Deny' ? 'Deny' : 'Allow';
    const action = stmt.Action as string | string[] | undefined;
    const conditions = extractTrustConditions(stmt);
    const conditional = !!conditions;

    const principal = stmt.Principal;

    // Wildcard form: "Principal": "*"
    if (principal === '*') {
      yield {
        principal: '*',
        principal_kind: 'wildcard',
        effect,
        action,
        conditions,
        conditional,
      };
      continue;
    }

    if (!principal || typeof principal !== 'object') continue;
    const p = principal as Record<string, unknown>;

    const emit = (kind: AwsPrincipalKind, value: unknown): AwsTrustGrant[] => {
      const arr = asStringArray(value);
      return arr.map(v => ({
        principal: v,
        principal_kind: kind,
        effect,
        action,
        conditions,
        conditional,
      }));
    };

    if (p.AWS !== undefined) for (const g of emit('aws', p.AWS)) yield g;
    if (p.Service !== undefined) for (const g of emit('service', p.Service)) yield g;
    if (p.Federated !== undefined) for (const g of emit('federated', p.Federated)) yield g;
    if (p.CanonicalUser !== undefined) for (const g of emit('canonical', p.CanonicalUser)) yield g;
  }
}

/**
 * Convert an AwsTrustCondition into a flat object suitable for spreading
 * into edge properties. Returns undefined when no conditions exist so
 * callers can omit the keys entirely on unconditional trusts.
 */
export function trustConditionsToEdgeProps(c: AwsTrustCondition | undefined):
  Record<string, unknown> | undefined {
  if (!c) return undefined;
  const out: Record<string, unknown> = { trust_conditional: true };
  if (c.external_id_required !== undefined) out.external_id_required = c.external_id_required;
  if (c.mfa_required) out.mfa_required = true;
  if (c.source_arn_restriction !== undefined) out.source_arn_restriction = c.source_arn_restriction;
  if (c.source_account_restriction !== undefined) out.source_account_restriction = c.source_account_restriction;
  if (c.raw_condition) out.trust_conditions_raw = c.raw_condition;
  return out;
}
