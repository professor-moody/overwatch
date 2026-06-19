// ============================================================
// Overwatch — Operator Query Interpreter (read-only NL → graph queries)
//
// Sibling to command-interpreter.ts. Where that turns NL into MUTATING
// OperatorOps (preview → confirm), this turns NL into READ-ONLY queries that
// resolve to existing read tools (get_state changes_since, get_timeline,
// query_graph, get_finding_readiness) and execute IMMEDIATELY — no confirm
// gate, because nothing mutates.
//
// Safety contract (enforced by the /api/commands route): interpretQuery runs
// BEFORE interpretCommand and short-circuits on a hit, so a string it claims
// never reaches the mutation grammar or the headless planner. Two rules keep it
// provably non-colliding and purely additive:
//   1. MUTATION_LEAD — return null the instant the text begins with a mutation
//      verb, so no input can be both a query and a mutation.
//   2. interpretQuery only claims text that matches a CONCRETE query pattern;
//      it never claims "anything that looks like a question" (that would starve
//      the headless planner of strategic NL requests). Unrecognized input → null
//      → the existing mutation/planner path runs byte-for-byte unchanged.
// ============================================================

import type { GraphEngine } from './graph-engine.js';
import type { NodeType } from '../types.js';
import { computeChangesSince } from './changes-since.js';
import { buildFindingReadiness, type Readiness } from './finding-readiness.js';
import { runRetrospective } from './retrospective.js';

// A query the operator asked, resolved to a read-only intent.
export type QueryOp =
  | { kind: 'changes_since'; since?: string }
  | { kind: 'timeline'; entity_id?: string; entity_kind?: 'node' | 'edge'; since?: string; at?: string; limit?: number }
  | { kind: 'list_nodes'; node_type?: NodeType; count_only: boolean; limit: number }
  | { kind: 'finding_readiness'; finding_id?: string; readiness?: Readiness; gaps_only?: boolean }
  | { kind: 'retrospective' };

/** Minimal structural view of a SkillIndex — keeps this module decoupled from
 *  the concrete class while letting the retrospective query read skill names. */
export interface SkillLister { listSkills(): Array<{ name: string; tags: string[] }> }

/** Execution context for read-only queries. `now` is injected for deterministic
 *  time math; `skills` is consulted only by the retrospective query. */
export interface QueryExecCtx { now?: Date; skills?: SkillLister | null }

// The rendered answer the command bar shows (small + flat so it renders without
// a sub-component). `summary` is always present; `rows` are pre-formatted lines.
// `unanswerable` is only ever produced by the route's catch (an execution
// error), never by interpretQuery.
export interface QueryAnswer {
  kind: QueryOp['kind'] | 'unanswerable';
  summary: string;
  rows?: string[];
  total?: number;
  note?: string;
}

// Mutation verbs own any string they lead. Mirror the four anchored regexes in
// command-interpreter.ts (interpretCommand). interpretQuery yields immediately
// when the text begins with one of these — the provable non-collision rule.
const MUTATION_LEAD = /^(pause|resume|stop|halt|tell|instruct|scan|add\s+scope|add\s+to\s+scope|target|approve|deny)\b/i;

const ROW_CAP = 20;        // max rows we render in the bar
const COUNT_PROBE = 1000;  // read cap when materializing node rows for resolution

// Singular/plural/slang → NodeType. Kept in sync with NODE_TYPES by a unit test.
export const NODE_TYPE_ALIASES: Record<string, NodeType> = {
  host: 'host', hosts: 'host', machine: 'host', machines: 'host', box: 'host', boxes: 'host', system: 'host', systems: 'host', server: 'host', servers: 'host',
  service: 'service', services: 'service', svc: 'service', port: 'service', ports: 'service',
  domain: 'domain', domains: 'domain',
  user: 'user', users: 'user', account: 'user', accounts: 'user',
  group: 'group', groups: 'group',
  cred: 'credential', creds: 'credential', credential: 'credential', credentials: 'credential', password: 'credential', passwords: 'credential', secret: 'credential', secrets: 'credential', hash: 'credential', hashes: 'credential',
  share: 'share', shares: 'share',
  cert: 'certificate', certs: 'certificate', certificate: 'certificate', certificates: 'certificate',
  ca: 'ca', cas: 'ca',
  'cert template': 'cert_template', 'cert templates': 'cert_template', 'certificate template': 'cert_template', 'certificate templates': 'cert_template', template: 'cert_template', templates: 'cert_template',
  'pki store': 'pki_store', 'pki stores': 'pki_store',
  gpo: 'gpo', gpos: 'gpo',
  ou: 'ou', ous: 'ou',
  subnet: 'subnet', subnets: 'subnet',
  objective: 'objective', objectives: 'objective', goal: 'objective', goals: 'objective',
  webapp: 'webapp', webapps: 'webapp', 'web app': 'webapp', 'web apps': 'webapp', website: 'webapp', websites: 'webapp', 'web application': 'webapp', 'web applications': 'webapp', site: 'webapp', sites: 'webapp',
  vuln: 'vulnerability', vulns: 'vulnerability', vulnerability: 'vulnerability', vulnerabilities: 'vulnerability', cve: 'vulnerability', cves: 'vulnerability',
  api: 'api_endpoint', apis: 'api_endpoint', 'api endpoint': 'api_endpoint', 'api endpoints': 'api_endpoint', endpoint: 'api_endpoint', endpoints: 'api_endpoint',
  'cloud identity': 'cloud_identity', 'cloud identities': 'cloud_identity',
  'cloud resource': 'cloud_resource', 'cloud resources': 'cloud_resource', bucket: 'cloud_resource', buckets: 'cloud_resource',
  'cloud policy': 'cloud_policy', 'cloud policies': 'cloud_policy',
  'cloud network': 'cloud_network', 'cloud networks': 'cloud_network', vpc: 'cloud_network', vpcs: 'cloud_network',
  idp: 'idp', idps: 'idp',
  'idp app': 'idp_application', 'idp apps': 'idp_application', 'idp application': 'idp_application', 'idp applications': 'idp_application',
  'idp principal': 'idp_principal', 'idp principals': 'idp_principal',
};

// ---- pure time parsing (now is injected for determinism; all math is UTC) ----

function unitToMs(u: string): number | null {
  if (/^(s|sec|secs|second|seconds)$/.test(u)) return 1_000;
  if (/^(m|min|mins|minute|minutes)$/.test(u)) return 60_000;
  if (/^(h|hr|hrs|hour|hours)$/.test(u)) return 3_600_000;
  if (/^(d|day|days)$/.test(u)) return 86_400_000;
  if (/^(w|wk|wks|week|weeks)$/.test(u)) return 604_800_000;
  return null;
}

function durationToMs(text: string): number | null {
  // numbered duration first ("15 minutes", "2h", "30m")
  const m = text.match(/(\d+)\s*([a-z]+)\b/);
  if (m) { const ms = unitToMs(m[2]); if (ms != null) return parseInt(m[1], 10) * ms; }
  // bare-unit windows with a qualifier ("the past hour", "last hour", "an hour")
  if (/\bhalf(\s+an?)?\s+hour\b/.test(text)) return 1_800_000;
  const QUAL = '(?:an?|one|the|last|past|previous|this)';
  if (new RegExp(`\\b${QUAL}\\s+hour\\b`).test(text)) return 3_600_000;
  if (new RegExp(`\\b${QUAL}\\s+minute\\b`).test(text)) return 60_000;
  if (new RegExp(`\\b${QUAL}\\s+day\\b`).test(text)) return 86_400_000;
  if (new RegExp(`\\b${QUAL}\\s+week\\b`).test(text)) return 604_800_000;
  return null;
}

function namedOrClockIso(text: string, now: Date): string | undefined {
  // setUTCHours (not setHours): timestamps in the graph are UTC ISO, so named/
  // clock times must be computed in UTC or every non-UTC server mis-windows.
  const atUtc = (h: number, mnt: number, rollBackIfFuture: boolean): string => {
    const d = new Date(now); d.setUTCHours(h, mnt, 0, 0);
    if (rollBackIfFuture && d.getTime() > now.getTime()) d.setUTCDate(d.getUTCDate() - 1);
    return d.toISOString();
  };
  if (/\byesterday\b/.test(text)) return new Date(now.getTime() - 86_400_000).toISOString();
  if (/\bthis\s+morning\b/.test(text)) return atUtc(9, 0, true);
  if (/\bnoon\b/.test(text)) return atUtc(12, 0, true);
  if (/\bmidnight\b/.test(text) || /\btoday\b/.test(text)) return atUtc(0, 0, false);
  // clock: "10am", "10:30", "since 14:00"
  const m = text.match(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b/) || text.match(/\bsince\s+(\d{1,2})(?::(\d{2}))?\b/);
  if (m) {
    let hh = parseInt(m[1], 10);
    const mnt = m[2] ? parseInt(m[2], 10) : 0;
    const ap = m[3];
    if (ap === 'pm' && hh < 12) hh += 12;
    if (ap === 'am' && hh === 12) hh = 0;
    if (hh > 23 || mnt > 59) return undefined;
    return atUtc(hh, mnt, true);
  }
  return undefined;
}

/** Resolve a free-form time clause to a normalized ISO-8601 string, or undefined
 *  if nothing parseable. ALWAYS returns canonical ISO so downstream string
 *  comparisons (queryTimeline does a lexicographic >= on `since`/`at`) stay
 *  correct against the engine's canonical `new Date().toISOString()` timestamps. */
function parseTimeWindow(text: string, now: Date): string | undefined {
  const iso = text.match(/\b(\d{4}-\d{2}-\d{2}(?:[t ][\d:.+\-z]+)?)\b/i);
  if (iso) { const ms = Date.parse(iso[1]); if (!Number.isNaN(ms)) return new Date(ms).toISOString(); }
  const dur = durationToMs(text);
  if (dur != null) return new Date(now.getTime() - dur).toISOString();
  return namedOrClockIso(text, now);
}

// ---- entity reference extraction ----

const IP_RE = /\b(\d{1,3}\.){3}\d{1,3}\b/;
const DOMAIN_RE = /\b(?=[a-z0-9.-]{4,})([a-z0-9-]+\.)+[a-z]{2,}\b/i;
const NODE_ID_RE = /\b[a-z][a-z0-9]*[-:][a-z0-9._:@-]+\b/i;
const DATE_OR_TIME_RE = /^(\d{4}-\d{2}-\d{2}|\d{1,2}:\d{2}|\d{1,2}(am|pm))/i;
const TIME_WORD_RE = /\b(since|yesterday|today|noon|midnight|this|morning|last|past|over|within|ago|limit|recent|latest|entries|events|items|changes|node|nodes|edge|edges|at|on|of|for|the|a|an)\b/;

/** Pull the first plausible entity reference out of a remainder string,
 *  ignoring time/date/kind/connective stopwords. Lenient by design (read-only;
 *  a wrong ref resolves to nothing, never to a mutation). */
function extractEntityRef(text: string): string | undefined {
  if (DATE_OR_TIME_RE.test(text.trim())) return undefined; // a leading date/time clause is not an entity
  const ip = text.match(IP_RE);
  if (ip) return ip[0];
  const dom = text.match(DOMAIN_RE);
  if (dom) return dom[0].toLowerCase();
  const id = text.match(NODE_ID_RE);
  if (id) return id[0];
  // bare token containing a digit (host7, dc01) that isn't a date/time or stopword
  for (const tok of text.split(/[\s,]+/)) {
    const t = tok.replace(/[?.!]+$/, '');
    if (t && /\d/.test(t) && !DATE_OR_TIME_RE.test(t) && !TIME_WORD_RE.test(t)) return t;
  }
  return undefined;
}

// ---- matchers (each pure, returns QueryOp | null) ----

function matchFindingReadiness(q: string): QueryOp | null {
  // "(any) new findings" is a changes_since digest (what's new), not a proof
  // -readiness audit — cede it so the changes_since trigger can claim it.
  if (/^(?:any\s+)?new\s+findings\b/.test(q) || /\bnew\s+findings\s+since\b/.test(q)) return null;
  const findingsTopic = /\bfindings?\b/.test(q);
  // Readiness vocabulary that signals the intent even without the word "finding".
  const readinessIntent = /\bclient[\s-]?ready\b/.test(q)
    || /\b(ready\s+to\s+report|reportable)\b/.test(q)
    || /\breadiness\b/.test(q)
    || /^(?:proof|evidence)\s+readiness$/.test(q);
  if (!findingsTopic && !readinessIntent) return null;

  const finding_id = q.match(/\bf-?\d+\b/)?.[0];

  let readiness: Readiness | undefined;
  if (/\bclient[\s-]?ready\b/.test(q) || /\b(ready\s+to\s+report|reportable|report[\s-]?ready|can\s+go\s+in\s+the\s+report|backed\s+by\s+evidence)\b/.test(q)) readiness = 'client_ready';
  else if (/\b(unvalidated|needs?\s+(?:more\s+)?(?:validation|proof|work)|still\s+needs?\s+(?:proof|validation|evidence))\b/.test(q)) readiness = 'needs_validation';
  else if (/\b(drafts?|thin|weak\s+findings?)\b/.test(q)) readiness = 'draft';

  let gaps_only: boolean | undefined;
  if (/\b(lacks?|lacking|missing|without|absent|no)\b[^.]*\b(evidence|proof)\b/.test(q)
    || /\b(ungrounded|unproven|unproved)\b/.test(q)
    || /\b(?:has|have|with|any)\s+gaps?\b/.test(q)
    || /\bwhat\s+gaps\b/.test(q)) gaps_only = true;

  return { kind: 'finding_readiness', finding_id, readiness, gaps_only };
}

function matchTimeline(q: string, now: Date): QueryOp | null {
  let entity_id: string | undefined;
  let at: string | undefined;
  let remainder: string | null = null;

  let entity_kind: 'node' | 'edge' | undefined;
  let m: RegExpMatchArray | null;
  // Optional leading "node(s)/edge(s)" before timeline/history ("edge timeline").
  if ((m = q.match(/^(?:show\s+(?:me\s+)?(?:the\s+)?)?(?:(node|edge)s?\s+)?(?:timeline|history|audit\s*trail|lifecycle)\b(.*)$/))) {
    if (m[1]) entity_kind = m[1] as 'node' | 'edge';
    remainder = m[2] ?? '';
  } else if ((m = q.match(/^what\s+happened\s+(?:to|with|on|for)\s+(.+)$/))) {
    entity_id = extractEntityRef(m[1]); remainder = '';
  } else if ((m = q.match(/^when\s+(?:did\s+we\s+(?:find|discover|see)|was)\s+(.+?)(?:\s+(?:discovered|found|first\s+seen))?$/))) {
    entity_id = extractEntityRef(m[1]); remainder = '';
  } else if ((m = q.match(/^(?:what(?:\s+was)?\s+true|state)\s+(?:at|on)\s+(.+)$/))) {
    const t = parseTimeWindow(m[1], now);
    if (!t) return null; // "what was true" with no parseable timestamp is not a timeline
    at = t; remainder = '';
  } else {
    return null;
  }

  let since: string | undefined;
  let limit: number | undefined;

  if (remainder) {
    // Strip each recognized clause out of `rem` as it's consumed, so the leftover
    // — and ONLY the leftover — is searched for an entity ref. Otherwise the
    // numbers in "last 24h" / "limit 50" leak into extractEntityRef as a bogus
    // entity_id, and the window is parsed off text that also holds the entity.
    let rem = ` ${remainder} `;

    if (!entity_kind) {
      const km = rem.match(/\b(node|edge)s?\b/);
      if (km) { entity_kind = km[1] as 'node' | 'edge'; rem = rem.replace(km[0], ' '); }
    }

    const lm = rem.match(/\blimit\s+(\d+)\b/)
      || rem.match(/\blast\s+(\d+)\s+(?:entries|events|items|changes)\b/)
      || rem.match(/\b(\d+)\s+(?:most\s+recent|recent|latest)\b/);
    if (lm) { limit = Math.min(2000, Math.max(1, parseInt(lm[1], 10))); rem = rem.replace(lm[0], ' '); }

    // "at/on <time>" is a point-in-time snapshot; a "since/last/relative" clause
    // is a window. They are mutually exclusive — never derive `since` from the
    // same words that produced `at` (that would collapse to an exact-instant filter).
    const atm = rem.match(/\b(?:at|on)\s+(.+?)\s*$/);
    if (atm) { const t = parseTimeWindow(atm[1], now); if (t) { at = t; rem = rem.replace(atm[0], ' '); } }
    if (!at) {
      const sinceM = rem.match(/\bsince\s+(.+?)\s*$/);
      if (sinceM) { since = parseTimeWindow(sinceM[1], now); rem = rem.replace(sinceM[0], ' '); }
      else {
        const winM = rem.match(/\b(?:in\s+the\s+|over\s+the\s+|within\s+the\s+)?(?:last|past|previous)\s+(?:\d+\s*)?[a-z]+\b|\bhalf\s+(?:an?\s+)?hour\b|\b\d+\s*[a-z]+\s+ago\b|\b(?:yesterday|today|noon|midnight)\b|\bthis\s+morning\b|\b\d{4}-\d{2}-\d{2}(?:[t ][\d:.+\-z]+)?\b/i);
        if (winM) { const t = parseTimeWindow(winM[0], now); if (t) { since = t; rem = rem.replace(winM[0], ' '); } }
      }
    }

    if (!entity_id) entity_id = extractEntityRef(rem);
  }

  return { kind: 'timeline', entity_id, entity_kind, since, at, limit };
}

function matchChangesSince(q: string, now: Date): QueryOp | null {
  const trigger = /^(?:what(?:'?s| is| did| has| have| 'd)?\s+(?:changed|new|happened|happening|been\s+happening|gone\s+on|different|progressed|the\s+latest)|whats?\s+(?:changed|new|happened)|anything\s+(?:new|happen(?:ed)?|finish(?:ed)?|complete[d]?|change[d]?)|any\s+(?:new\s+)?updates?|updates?|new\s+findings|any\s+new\s+findings|which\s+agents?\s+(?:finished|completed)|what\s+(?:completed|finished|moved|progressed)|recap|catch\s+me\s+up|bring\s+me\s+up\s+to\s+speed|fill\s+me\s+in|digest|changes(?:\s+digest)?|diff|show\s+(?:me\s+)?(?:recent\s+)?changes|show\s+updates|summari[sz]e\s+(?:what\s+changed|recent\s+activity|changes)|latest\s+changes|recent\s+changes)\b/;
  if (!trigger.test(q)) return null;
  // vague "since I last looked / last check / recently" → no explicit window
  const hasExplicitTime = /\b(since|last|past|over|within|ago|in\s+the\s+last|\d{4}-\d{2}-\d{2}|am|pm|yesterday|today|noon|midnight|this\s+morning)\b/.test(q)
    && !/\bsince\s+(?:i\s+)?last\b/.test(q) && !/\blast\s+(?:check|time|look|looked|poll|sync)\b/.test(q);
  const since = hasExplicitTime ? parseTimeWindow(q, now) : undefined;
  return { kind: 'changes_since', since };
}

function matchRetrospective(q: string): QueryOp | null {
  if (/\b(retrospective|retro|post[\s-]?mortem)\b/.test(q)
    || /\bwhat\s+(worked|wasted\s+time|went\s+(well|wrong)|did\s+we\s+learn)\b/.test(q)
    || /\blessons\s+learned\b/.test(q)
    || /\bwhat\s+should\s+the\s+next\s+operator\b/.test(q)) {
    return { kind: 'retrospective' };
  }
  return null;
}

function matchListNodes(q: string): QueryOp | null {
  // count intent
  let count_only = false;
  let body = q;
  const countm = q.match(/^(?:how\s+many|count(?:\s+of)?|number\s+of|num(?:ber)?\s+of|tally\s+of|total(?:\s+number\s+of)?)\s+(.+)$/);
  if (countm) { count_only = true; body = countm[1]; }

  // strip leading list/show verbs + leading filler (stacked determiners: "all the")
  body = body.replace(/^(?:list|show|display|enumerate|give\s+me|get|find|what|which)\s+/, '')
             .replace(/^(?:me\s+)?/, '')
             .replace(/^(?:(?:all|every|the)\s+)+/, '');

  // limit: "top N <type>" / "first N <type>" / "<type> limit N"
  let limit = 25;
  const topm = body.match(/^(?:top|first)\s+(\d+)\s+/) || body.match(/\blimit\s+(\d+)\b/);
  if (topm) { limit = Math.min(100, Math.max(1, parseInt(topm[1], 10))); body = body.replace(topm[0], ' '); }

  // strip trailing filler
  body = body.replace(/\b(?:do|did)\s+we\s+(?:have|find|discover|got|get)\b.*$/, '')
             .replace(/\b(?:are|is)\s+there\b.*$/, '')
             .replace(/\bin\s+(?:the\s+)?(?:graph|scope|engagement)\b.*$/, '')
             .replace(/\b(?:so\s+far|total|in\s+total)\b.*$/, '')
             .replace(/\bhave\s+we\s+found\b.*$/, '')
             .trim();

  // generic whole-graph
  if (/^(nodes?|graph|everything|all)$/.test(body)) return { kind: 'list_nodes', count_only, limit };

  const key = body.replace(/[_-]/g, ' ').replace(/\s+/g, ' ').trim();
  const node_type = NODE_TYPE_ALIASES[key];
  if (!node_type) return null; // unresolved type → no guess, fall through
  return { kind: 'list_nodes', node_type, count_only, limit };
}

/**
 * Deterministic NL → read-only QueryOp. Pure. Returns null when the text is not
 * a recognized query (so the caller falls through to the mutation grammar /
 * planner unchanged — interpretQuery never claims "anything that looks like a
 * question"). `now` is injected for deterministic time parsing.
 */
export function interpretQuery(rawText: string, now: Date = new Date()): QueryOp | null {
  const text = rawText.trim();
  if (!text) return null;
  if (MUTATION_LEAD.test(text)) return null; // a mutation owns any string it leads
  const q = text.toLowerCase().replace(/\?+\s*$/, '').trim();
  if (!q) return null;

  return matchFindingReadiness(q)
    ?? matchRetrospective(q)
    ?? matchTimeline(q, now)
    ?? matchChangesSince(q, now)
    ?? matchListNodes(q);
}

// ---- execution (read-only) ----

function nodeRow(n: { id: string; properties: { label?: string; ip?: string; hostname?: string } }): string {
  const name = n.properties.label || n.properties.hostname || n.id;
  const ip = n.properties.ip && !name.includes(n.properties.ip) ? ` (${n.properties.ip})` : '';
  return `${name}${ip}`;
}

/** Resolve a free-form ref to a single node id, or report the candidates.
 *  Mirrors the resolveTasks/resolveActionId discipline: exact id → IP/label
 *  substring. Used to turn a typed "10.0.0.5"/"dc01" into the structured node id
 *  the timeline/graph store actually keys on. */
function resolveNodeRef(engine: GraphEngine, ref: string): { id?: string; candidates: string[] } {
  const all = engine.queryGraph({ node_filter: {}, limit: COUNT_PROBE }).nodes;
  const lower = ref.toLowerCase();
  const exact = all.find(n => n.id === ref || n.id.toLowerCase() === lower);
  if (exact) return { id: exact.id, candidates: [exact.id] };
  // Exact IP/hostname-property match BEFORE the substring fallback, so "10.0.0.5"
  // resolves to its host even when "10.0.0.50" also exists (substring would tie).
  const propExact = all.filter(n => n.properties.ip === ref || (n.properties.hostname ?? '').toLowerCase() === lower);
  if (propExact.length === 1) return { id: propExact[0].id, candidates: [propExact[0].id] };
  const matches = all.filter(n => {
    const hay = `${n.id} ${n.properties.label ?? ''} ${n.properties.hostname ?? ''} ${n.properties.ip ?? ''}`.toLowerCase();
    return hay.includes(lower);
  });
  if (matches.length === 1) return { id: matches[0].id, candidates: [matches[0].id] };
  return { candidates: matches.slice(0, 5).map(n => n.id) };
}

/** Execute a read-only QueryOp against the engine. Never mutates. Each branch
 *  returns a valid answer on empty/bad input rather than throwing. */
export function executeQuery(engine: GraphEngine, op: QueryOp, ctx: QueryExecCtx = {}): QueryAnswer {
  const now = ctx.now ?? new Date();
  switch (op.kind) {
    case 'changes_since': {
      // No explicit window → the last 15 minutes (stated in the summary).
      const since = op.since ?? new Date(now.getTime() - 15 * 60_000).toISOString();
      const d = computeChangesSince(engine.getFullHistory(), since);
      if (!d) return { kind: 'changes_since', summary: 'Could not parse that time window.', note: 'Try "what changed in the last hour" or "since 2026-06-18T10:00Z".' };
      const rows: string[] = [];
      if (d.findings) rows.push(`${d.findings} new finding event(s)`);
      if (d.agents_completed) rows.push(`${d.agents_completed} agent(s) completed: ${d.completed_agent_ids.join(', ')}`);
      rows.push(`${d.total_events} total event(s)`);
      return { kind: 'changes_since', summary: op.since ? `Since ${d.since}:` : 'In the last 15 min:', rows, note: d.recommendation };
    }

    case 'timeline': {
      // Resolve a typed entity ref ("10.0.0.5", "dc01") to the structured node id
      // the timeline keys on; a bare ref never matches the stored id directly.
      let entityId = op.entity_id;
      if (op.entity_id) {
        const r = resolveNodeRef(engine, op.entity_id);
        if (r.id) entityId = r.id;
        else if (r.candidates.length > 1) return { kind: 'timeline', summary: `"${op.entity_id}" matches ${r.candidates.length} nodes — be specific.`, rows: r.candidates };
        else return { kind: 'timeline', summary: `No node matches "${op.entity_id}".`, rows: [] };
      }
      const entries = engine.getTimeline({ entity_id: entityId, kind: op.entity_kind, since: op.since, at: op.at, limit: op.limit ?? 50 });
      const scope = op.entity_id ? ` for ${op.entity_id}` : '';
      if (entries.length === 0) return { kind: 'timeline', summary: `No timeline entries${scope}.`, rows: [], total: 0 };
      const rows = entries.slice(0, ROW_CAP).map(e => {
        const closed = e.became_false_at ? ` … false @ ${e.became_false_at}` : '';
        return `${e.became_true_at}  ${e.entity_id} (${e.kind})${closed}`;
      });
      return { kind: 'timeline', summary: `${entries.length} timeline entr${entries.length === 1 ? 'y' : 'ies'}${scope}:`, rows, total: entries.length, note: entries.length > ROW_CAP ? `showing first ${ROW_CAP} of ${entries.length}` : undefined };
    }

    case 'list_nodes': {
      // Exact counts come from the engine's graph_summary (unbounded), not from a
      // capped queryGraph probe — so "how many hosts" is never silently truncated.
      const gs = engine.getState().graph_summary;
      const total = op.node_type ? (gs.nodes_by_type[op.node_type] ?? 0) : gs.total_nodes;
      const typeLabel = op.node_type ?? 'node';
      if (op.count_only) return { kind: 'list_nodes', summary: `${total} ${typeLabel}${total === 1 ? '' : 's'}`, total };
      if (total === 0) return { kind: 'list_nodes', summary: `No ${typeLabel}s in the graph.`, rows: [], total: 0 };
      const shown = engine.queryGraph({ node_type: op.node_type, node_filter: {}, limit: Math.min(op.limit, ROW_CAP) }).nodes;
      return {
        kind: 'list_nodes',
        summary: `${total} ${typeLabel}${total === 1 ? '' : 's'}:`,
        rows: shown.map(nodeRow),
        total,
        note: total > shown.length ? `showing first ${shown.length} of ${total}` : undefined,
      };
    }

    case 'finding_readiness': {
      const { summary, findings } = buildFindingReadiness(engine, op.finding_id);
      let fs = findings;
      if (op.readiness) fs = fs.filter(f => f.readiness === op.readiness);
      if (op.gaps_only) fs = fs.filter(f => f.readiness !== 'client_ready');
      const head = op.readiness || op.gaps_only || op.finding_id
        ? `${fs.length} finding(s)${op.readiness ? ` (${op.readiness})` : ''}${op.gaps_only ? ' with gaps' : ''}:`
        : `Findings — ${summary.client_ready} client-ready, ${summary.needs_validation} need validation, ${summary.draft} draft:`;
      if (fs.length === 0) return { kind: 'finding_readiness', summary: head, rows: [], total: 0 };
      const rows = fs.slice(0, ROW_CAP).map(f => `[${f.readiness}] ${f.title} (${f.severity})${f.gaps.length ? ` — ${f.gaps[0]}` : ''}`);
      return { kind: 'finding_readiness', summary: head, rows, total: fs.length, note: fs.length > ROW_CAP ? `showing first ${ROW_CAP} of ${fs.length}` : undefined };
    }

    case 'retrospective': {
      const allSkills = ctx.skills ? ctx.skills.listSkills() : [];
      const result = runRetrospective({
        config: engine.getConfig(),
        graph: engine.exportGraph(),
        history: engine.getFullHistory(),
        inferenceRules: engine.getInferenceRules(),
        agents: engine.getAllAgents(),
        skillNames: allSkills.map(s => s.name),
        skillTags: allSkills.flatMap(s => s.tags),
      });
      // The structured `summary` is a clean digest (objectives, agents, gaps);
      // append the actionable context-improvement recommendations.
      const digest = result.summary.split('\n').filter(l => l && l !== '---');
      const recs = (result.context_improvements.recommendations ?? []).slice(0, 5).map(r => `→ ${r}`);
      return {
        kind: 'retrospective',
        summary: `Retrospective — ${result.inference_suggestions.length} inference suggestion(s), ${result.skill_gaps.missing_skills.length} skill gap(s)`,
        rows: [...digest, ...recs],
        note: 'Full narrative report: Findings → Reports → Generate Report (include retrospective).',
      };
    }
  }
}
