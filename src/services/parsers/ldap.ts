import type { Finding, EdgeType } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { domainId, groupId, hostId, normalizeKeyPart, userId } from '../parser-utils.js';

// --- ldapsearch / ldapdomaindump Parser ---

// UAC bit for "Do not require Kerberos preauthentication"
const UAC_DONT_REQUIRE_PREAUTH = 0x400000;
// UAC bit for disabled account
const UAC_ACCOUNTDISABLE = 0x0002;
// S2-2: delegation UAC bits. Unconstrained delegation lets the principal
// forward any TGT it receives; trusted-to-auth-for-delegation flags accounts
// that participate in S4U2Self/S4U2Proxy flows (protocol transition).
const UAC_TRUSTED_FOR_DELEGATION = 0x80000;
const UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000;

interface DelegationProps {
  unconstrained_delegation?: true;
  trusted_to_auth_for_delegation?: true;
  rbcd_target?: true;
}

function delegationPropsFromUac(uac: number, hasRbcdAttr: boolean): DelegationProps {
  const out: DelegationProps = {};
  if (uac & UAC_TRUSTED_FOR_DELEGATION) out.unconstrained_delegation = true;
  if (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) out.trusted_to_auth_for_delegation = true;
  if (hasRbcdAttr) out.rbcd_target = true;
  return out;
}

/**
 * Extract the host portion of an SPN. e.g.:
 *   "cifs/dc01.lab.local"            -> "dc01.lab.local"
 *   "MSSQLSvc/sql.lab.local:1433"    -> "sql.lab.local"
 *   "HOST/WS01"                      -> "ws01"
 * Returns lowercase. Returns undefined for shapes we don't recognize.
 */
function hostFromSpn(spn: string): string | undefined {
  if (typeof spn !== 'string') return undefined;
  const slashIdx = spn.indexOf('/');
  if (slashIdx < 0) return undefined;
  const after = spn.slice(slashIdx + 1);
  const colonIdx = after.indexOf(':');
  const host = (colonIdx < 0 ? after : after.slice(0, colonIdx)).trim().toLowerCase();
  return host.length > 0 ? host : undefined;
}

function domainFromDn(dn: string): string | undefined {
  const dcParts: string[] = [];
  for (const part of dn.split(',')) {
    const m = part.trim().match(/^DC=(.+)$/i);
    if (m) dcParts.push(m[1]);
  }
  return dcParts.length > 0 ? dcParts.join('.') : undefined;
}

/**
 * Parse AD time interval attributes (stored as negative 100-nanosecond intervals).
 * e.g., minPwdAge/maxPwdAge/lockoutDuration are stored as negative large integers.
 * Returns absolute value in seconds, or undefined if unparseable/zero.
 */
function parseADTimeInterval(values: string[] | undefined): number | undefined {
  if (!values || values.length === 0) return undefined;
  const raw = values[0].trim();
  if (!raw || raw === '0') return undefined;
  // AD stores these as negative 100-nanosecond intervals
  // e.g., -36288000000000 = 42 days in 100ns units
  // F12: a single malformed attribute (e.g. minPwdAge: "notnum") used to
  // throw and abort the entire LDIF parse, losing all valid users/groups
  // downstream. Treat unparseable intervals as undefined.
  let val: bigint;
  try {
    val = BigInt(raw);
  } catch {
    return undefined;
  }
  if (val === 0n) return undefined;
  const absVal = val < 0n ? -val : val;
  // Convert 100-nanosecond intervals to seconds
  return Number(absVal / 10_000_000n);
}

/**
 * Convert Windows FILETIME (100-nanosecond intervals since 1601-01-01) to ISO string.
 * Returns undefined for never-set values (0, max int).
 */
function adFileTimeToISO(values: string[] | undefined): string | undefined {
  if (!values || values.length === 0) return undefined;
  const raw = values[0].trim();
  if (!raw || raw === '0' || raw === '9223372036854775807') return undefined;
  try {
    // Windows epoch offset: 1601-01-01 to 1970-01-01 in milliseconds
    const EPOCH_OFFSET = 11644473600000n;
    const filetime = BigInt(raw);
    const msFromWindowsEpoch = filetime / 10_000n;
    const unixMs = msFromWindowsEpoch - EPOCH_OFFSET;
    const date = new Date(Number(unixMs));
    if (isNaN(date.getTime())) return undefined;
    return date.toISOString();
  } catch {
    return undefined;
  }
}

function parseLdifStanzas(raw: string): Array<Record<string, string[]>> {
  // Handle line continuations (leading space = continuation of previous line)
  const unfolded = raw.replace(/\r?\n /g, '');
  const stanzas: Array<Record<string, string[]>> = [];
  let current: Record<string, string[]> = {};
  let hasContent = false;

  for (const line of unfolded.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) {
      if (hasContent) {
        stanzas.push(current);
        current = {};
        hasContent = false;
      }
      continue;
    }
    // base64-encoded: attr:: base64value
    const b64Match = trimmed.match(/^([^:]+)::\s*(.*)$/);
    if (b64Match) {
      const [, attr, b64val] = b64Match;
      const key = attr.toLowerCase();
      let decoded: string;
      try {
        decoded = Buffer.from(b64val, 'base64').toString('utf-8');
      } catch {
        decoded = b64val;
      }
      (current[key] ??= []).push(decoded);
      hasContent = true;
      continue;
    }
    // Normal: attr: value
    const normalMatch = trimmed.match(/^([^:]+):\s*(.*)$/);
    if (normalMatch) {
      const [, attr, val] = normalMatch;
      (current[attr.toLowerCase()] ??= []).push(val);
      hasContent = true;
    }
  }
  if (hasContent) stanzas.push(current);
  return stanzas;
}

export function parseLdapsearch(output: string, agentId: string = 'ldapsearch-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();
  const now = new Date().toISOString();

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number, extra?: Record<string, unknown>): void {
    const key = `${source}--${type}--${target}`;
    if (seenEdges.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId, ...(extra ?? {}) } });
    seenEdges.add(key);
  }

  // Try ldapdomaindump JSON first
  try {
    const data = JSON.parse(output);
    if (Array.isArray(data) && data.length > 0 && data[0].attributes) {
      return parseLdapdomaindumpJson(data, agentId);
    }
  } catch {
    // Not JSON — parse as LDIF
  }

  const stanzas = parseLdifStanzas(output);
  for (const entry of stanzas) {
    const objectClass = (entry['objectclass'] || []).map(c => c.toLowerCase());
    const dn = (entry['dn'] || [''])[0];
    const domain = domainFromDn(dn);
    const sam = (entry['samaccountname'] || [''])[0];

    // Domain password policy from domainDNS objects
    if (objectClass.includes('domaindns') || objectClass.includes('domain')) {
      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        const domainNode = nodes.find(n => n.id === resolvedDomainId);
        if (domainNode) {
          const minPwdAge = parseADTimeInterval(entry['minpwdage']);
          const maxPwdAge = parseADTimeInterval(entry['maxpwdage']);
          const pwdHistLen = parseInt((entry['pwdhistorylength'] || [''])[0], 10);
          const minPwdLen = parseInt((entry['minpwdlength'] || [''])[0], 10);
          const lockoutThreshold = parseInt((entry['lockoutthreshold'] || [''])[0], 10);
          const lockoutDuration = parseADTimeInterval(entry['lockoutduration']);
          const lockoutWindow = parseADTimeInterval(entry['lockoutobservationwindow']);

          if (maxPwdAge !== undefined || minPwdAge !== undefined || !isNaN(pwdHistLen) || !isNaN(minPwdLen)) {
            domainNode.password_policy = {
              ...(minPwdAge !== undefined ? { min_pwd_age: minPwdAge } : {}),
              ...(maxPwdAge !== undefined ? { max_pwd_age: maxPwdAge } : {}),
              ...(!isNaN(pwdHistLen) ? { pwd_history_length: pwdHistLen } : {}),
              ...(!isNaN(minPwdLen) ? { min_pwd_length: minPwdLen } : {}),
            };
          }
          if (!isNaN(lockoutThreshold) || lockoutDuration !== undefined || lockoutWindow !== undefined) {
            domainNode.lockout_policy = {
              ...(!isNaN(lockoutThreshold) ? { lockout_threshold: lockoutThreshold } : {}),
              ...(lockoutDuration !== undefined ? { lockout_duration: lockoutDuration } : {}),
              ...(lockoutWindow !== undefined ? { lockout_observation_window: lockoutWindow } : {}),
            };
          }
        }
      }
      // domainDNS objects may not have sAMAccountName, so don't skip
      if (!sam) continue;
    }

    if (!sam) continue;

    // Computer objects — check BEFORE user/person since AD computers have
    // objectClass: top, person, organizationalPerson, user, computer
    if (objectClass.includes('computer')) {
      const dnsHostname = (entry['dnshostname'] || [''])[0];
      const osVal = (entry['operatingsystem'] || [''])[0] || undefined;
      const ip = dnsHostname || sam.replace(/\$$/, '');
      const resolvedHostId = dnsHostname ? `host-${normalizeKeyPart(dnsHostname)}` : hostId(ip);
      if (seenNodes.has(resolvedHostId)) continue;

      // S2-2: delegation attributes on computer accounts.
      const compUac = parseInt((entry['useraccountcontrol'] || ['0'])[0], 10) || 0;
      const compDelegateTo = entry['msds-allowedtodelegateto'] || [];
      const compRbcd = (entry['msds-allowedtoactonbehalfofotheridentity'] || []).length > 0;
      const delegationProps = delegationPropsFromUac(compUac, compRbcd);

      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: dnsHostname || sam,
        hostname: dnsHostname || undefined,
        os: osVal,
        domain_joined: true,
        alive: true,
        ...delegationProps,
      });
      seenNodes.add(resolvedHostId);

      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedHostId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }

      // S2-2: constrained delegation targets — emit CAN_DELEGATE_TO per SPN
      // whose host suffix we can resolve. We create placeholder host nodes
      // for unresolved SPNs so the edge is always anchored.
      for (const spn of compDelegateTo) {
        const targetHost = hostFromSpn(spn);
        if (!targetHost) continue;
        const targetHostId = `host-${normalizeKeyPart(targetHost)}`;
        if (!seenNodes.has(targetHostId)) {
          nodes.push({ id: targetHostId, type: 'host', label: targetHost, hostname: targetHost });
          seenNodes.add(targetHostId);
        }
        addEdgeOnce(resolvedHostId, targetHostId, 'CAN_DELEGATE_TO', 0.9, { spn });
      }
      continue;
    }

    // User objects (only reaches here if NOT a computer)
    if (objectClass.includes('person') || objectClass.includes('user')) {
      const resolvedUserId = userId(sam, domain);
      if (seenNodes.has(resolvedUserId)) continue;

      const uacRaw = parseInt((entry['useraccountcontrol'] || ['0'])[0], 10) || 0;
      const spns = entry['serviceprincipalname'] || [];
      const adminCount = (entry['admincount'] || ['0'])[0];
      const displayName = (entry['displayname'] || [''])[0] || undefined;
      const sidVal = (entry['objectsid'] || [''])[0] || undefined;
      const enabled = !(uacRaw & UAC_ACCOUNTDISABLE);
      const pwdLastSet = adFileTimeToISO(entry['pwdlastset']);
      // S2-2: delegation attributes on user accounts (service accounts
      // typically carry constrained delegation here, not on computers).
      const userDelegateTo = entry['msds-allowedtodelegateto'] || [];
      const userRbcd = (entry['msds-allowedtoactonbehalfofotheridentity'] || []).length > 0;
      const userDelegationProps = delegationPropsFromUac(uacRaw, userRbcd);

      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: domain ? `${domain}\\${sam}` : sam,
        username: sam,
        domain_name: domain,
        display_name: displayName,
        enabled,
        has_spn: spns.length > 0 || undefined,
        asrep_roastable: !!(uacRaw & UAC_DONT_REQUIRE_PREAUTH) || undefined,
        privileged: adminCount === '1' || undefined,
        sid: sidVal,
        pwd_last_set: pwdLastSet,
        ...userDelegationProps,
      });
      seenNodes.add(resolvedUserId);

      // Domain membership
      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }

      // Group memberships
      for (const memberOf of entry['memberof'] || []) {
        const groupCn = memberOf.match(/^CN=([^,]+)/i);
        if (groupCn) {
          const resolvedGroupId = groupId(groupCn[1], domain);
          if (!seenNodes.has(resolvedGroupId)) {
            nodes.push({ id: resolvedGroupId, type: 'group', label: groupCn[1], domain_name: domain });
            seenNodes.add(resolvedGroupId);
          }
          addEdgeOnce(resolvedUserId, resolvedGroupId, 'MEMBER_OF', 1.0);
        }
      }

      // S2-2: constrained delegation targets from user/service accounts.
      for (const spn of userDelegateTo) {
        const targetHost = hostFromSpn(spn);
        if (!targetHost) continue;
        const targetHostId = `host-${normalizeKeyPart(targetHost)}`;
        if (!seenNodes.has(targetHostId)) {
          nodes.push({ id: targetHostId, type: 'host', label: targetHost, hostname: targetHost });
          seenNodes.add(targetHostId);
        }
        addEdgeOnce(resolvedUserId, targetHostId, 'CAN_DELEGATE_TO', 0.9, { spn });
      }
      continue;
    }

    // Group objects
    if (objectClass.includes('group')) {
      const resolvedGroupId = groupId(sam, domain);
      if (seenNodes.has(resolvedGroupId)) continue;

      const sidVal = (entry['objectsid'] || [''])[0] || undefined;
      const adminCount = (entry['admincount'] || ['0'])[0];
      nodes.push({
        id: resolvedGroupId,
        type: 'group',
        label: sam,
        domain_name: domain,
        sid: sidVal,
        privileged: adminCount === '1' || undefined,
      });
      seenNodes.add(resolvedGroupId);
      continue;
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}

function parseLdapdomaindumpJson(data: Record<string, unknown>[], agentId: string): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();
  const now = new Date().toISOString();

  function addEdgeOnce(source: string, target: string, type: EdgeType, confidence: number, extra?: Record<string, unknown>): void {
    const key = `${source}--${type}--${target}`;
    if (seenEdges.has(key)) return;
    edges.push({ source, target, properties: { type, confidence, discovered_at: now, discovered_by: agentId, ...(extra ?? {}) } });
    seenEdges.add(key);
  }

  for (const entry of data) {
    const attrs = (entry.attributes ?? entry) as Record<string, unknown>;
    const objectClass = (Array.isArray(attrs.objectClass) ? attrs.objectClass as string[] : []).map((c: string) => c.toLowerCase());
    const sam = ((Array.isArray(attrs.sAMAccountName) ? attrs.sAMAccountName[0] : attrs.sAMAccountName) || '') as string;
    const dn = ((Array.isArray(attrs.distinguishedName) ? attrs.distinguishedName[0] : attrs.distinguishedName) || '') as string;
    const domain = domainFromDn(dn);

    // Domain password policy from domainDNS objects
    if (objectClass.includes('domaindns') || objectClass.includes('domain')) {
      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        const domainNode = nodes.find(n => n.id === resolvedDomainId);
        if (domainNode) {
          const getNum = (key: string): number | undefined => {
            const v = attrs[key];
            const n = parseInt(String(Array.isArray(v) ? v[0] : v), 10);
            return isNaN(n) ? undefined : n;
          };
          const getTimeInterval = (key: string): number | undefined => {
            const v = attrs[key];
            const raw = String(Array.isArray(v) ? v[0] : v || '').trim();
            if (!raw || raw === '0' || raw === 'undefined') return undefined;
            try {
              const val = BigInt(raw);
              if (val === 0n) return undefined;
              const absVal = val < 0n ? -val : val;
              return Number(absVal / 10_000_000n);
            } catch { return undefined; }
          };
          const maxPwdAge = getTimeInterval('maxPwdAge');
          const minPwdAge = getTimeInterval('minPwdAge');
          const pwdHistLen = getNum('pwdHistoryLength');
          const minPwdLen = getNum('minPwdLength');
          const lockoutThreshold = getNum('lockoutThreshold');
          const lockoutDuration = getTimeInterval('lockoutDuration');
          const lockoutWindow = getTimeInterval('lockOutObservationWindow');

          if (maxPwdAge !== undefined || minPwdAge !== undefined || pwdHistLen !== undefined || minPwdLen !== undefined) {
            domainNode.password_policy = {
              ...(minPwdAge !== undefined ? { min_pwd_age: minPwdAge } : {}),
              ...(maxPwdAge !== undefined ? { max_pwd_age: maxPwdAge } : {}),
              ...(pwdHistLen !== undefined ? { pwd_history_length: pwdHistLen } : {}),
              ...(minPwdLen !== undefined ? { min_pwd_length: minPwdLen } : {}),
            };
          }
          if (lockoutThreshold !== undefined || lockoutDuration !== undefined || lockoutWindow !== undefined) {
            domainNode.lockout_policy = {
              ...(lockoutThreshold !== undefined ? { lockout_threshold: lockoutThreshold } : {}),
              ...(lockoutDuration !== undefined ? { lockout_duration: lockoutDuration } : {}),
              ...(lockoutWindow !== undefined ? { lockout_observation_window: lockoutWindow } : {}),
            };
          }
        }
      }
      if (!sam) continue;
    }

    if (!sam) continue;

    // Computer objects — check BEFORE user/person since AD computers have
    // objectClass: top, person, organizationalPerson, user, computer
    if (objectClass.includes('computer')) {
      const dnsHostname = (attrs.dNSHostName || attrs.dnshostname || '') as string;
      const osVal = (attrs.operatingSystem as string) || undefined;
      const resolvedHostId = dnsHostname ? `host-${normalizeKeyPart(dnsHostname)}` : `host-${normalizeKeyPart(sam)}`;
      if (seenNodes.has(resolvedHostId)) continue;

      // S2-2: delegation attributes on computer accounts.
      const compUac = parseInt(String(attrs.userAccountControl || '0'), 10) || 0;
      const compDelegateToRaw = attrs['msDS-AllowedToDelegateTo'] ?? attrs['msds-allowedtodelegateto'];
      const compDelegateTo: string[] = Array.isArray(compDelegateToRaw)
        ? compDelegateToRaw.filter((v): v is string => typeof v === 'string')
        : typeof compDelegateToRaw === 'string' ? [compDelegateToRaw] : [];
      const compRbcdRaw = attrs['msDS-AllowedToActOnBehalfOfOtherIdentity'] ?? attrs['msds-allowedtoactonbehalfofotheridentity'];
      const compHasRbcd = compRbcdRaw !== undefined && compRbcdRaw !== null
        && !(Array.isArray(compRbcdRaw) && compRbcdRaw.length === 0);
      const delegationProps = delegationPropsFromUac(compUac, compHasRbcd);

      nodes.push({
        id: resolvedHostId,
        type: 'host',
        label: dnsHostname || sam,
        hostname: dnsHostname || undefined,
        os: osVal,
        domain_joined: true,
        alive: true,
        ...delegationProps,
      });
      seenNodes.add(resolvedHostId);

      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedHostId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }

      // S2-2: constrained delegation targets — placeholder host nodes for
      // unresolved SPNs so the edge is always anchored.
      for (const spn of compDelegateTo) {
        const targetHost = hostFromSpn(spn);
        if (!targetHost) continue;
        const targetHostId = `host-${normalizeKeyPart(targetHost)}`;
        if (!seenNodes.has(targetHostId)) {
          nodes.push({ id: targetHostId, type: 'host', label: targetHost, hostname: targetHost });
          seenNodes.add(targetHostId);
        }
        addEdgeOnce(resolvedHostId, targetHostId, 'CAN_DELEGATE_TO', 0.9, { spn });
      }
      continue;
    }

    if (objectClass.includes('person') || objectClass.includes('user')) {
      const resolvedUserId = userId(sam, domain);
      if (seenNodes.has(resolvedUserId)) continue;

      const uac = parseInt(String(attrs.userAccountControl || '0'), 10) || 0;
      const spns = attrs.servicePrincipalName || [];
      const adminCount = String(attrs.adminCount || '0');
      const pwdLastSetRaw = String(attrs.pwdLastSet || '');
      const pwdLastSet = adFileTimeToISO([pwdLastSetRaw]);
      // S2-2: delegation attributes on user/service accounts.
      const userDelegateToRaw = attrs['msDS-AllowedToDelegateTo'] ?? attrs['msds-allowedtodelegateto'];
      const userDelegateTo: string[] = Array.isArray(userDelegateToRaw)
        ? userDelegateToRaw.filter((v): v is string => typeof v === 'string')
        : typeof userDelegateToRaw === 'string' ? [userDelegateToRaw] : [];
      const userRbcdRaw = attrs['msDS-AllowedToActOnBehalfOfOtherIdentity'] ?? attrs['msds-allowedtoactonbehalfofotheridentity'];
      const userHasRbcd = userRbcdRaw !== undefined && userRbcdRaw !== null
        && !(Array.isArray(userRbcdRaw) && userRbcdRaw.length === 0);
      const userDelegationProps = delegationPropsFromUac(uac, userHasRbcd);

      nodes.push({
        id: resolvedUserId,
        type: 'user',
        label: domain ? `${domain}\\${sam}` : sam,
        username: sam,
        domain_name: domain,
        display_name: (attrs.displayName as string) || undefined,
        enabled: !(uac & UAC_ACCOUNTDISABLE),
        has_spn: (Array.isArray(spns) ? spns.length > 0 : !!spns) || undefined,
        asrep_roastable: !!(uac & UAC_DONT_REQUIRE_PREAUTH) || undefined,
        privileged: adminCount === '1' || undefined,
        sid: (attrs.objectSid as string) || undefined,
        pwd_last_set: pwdLastSet,
        ...userDelegationProps,
      });
      seenNodes.add(resolvedUserId);

      if (domain) {
        const resolvedDomainId = domainId(domain);
        if (!seenNodes.has(resolvedDomainId)) {
          nodes.push({ id: resolvedDomainId, type: 'domain', label: domain, domain_name: domain });
          seenNodes.add(resolvedDomainId);
        }
        addEdgeOnce(resolvedUserId, resolvedDomainId, 'MEMBER_OF_DOMAIN', 1.0);
      }

      for (const memberOf of (Array.isArray(attrs.memberOf) ? attrs.memberOf as string[] : [])) {
        const groupCn = memberOf.match(/^CN=([^,]+)/i);
        if (groupCn) {
          const resolvedGroupId = groupId(groupCn[1], domain);
          if (!seenNodes.has(resolvedGroupId)) {
            nodes.push({ id: resolvedGroupId, type: 'group', label: groupCn[1], domain_name: domain });
            seenNodes.add(resolvedGroupId);
          }
          addEdgeOnce(resolvedUserId, resolvedGroupId, 'MEMBER_OF', 1.0);
        }
      }

      // S2-2: constrained delegation targets from user/service accounts.
      for (const spn of userDelegateTo) {
        const targetHost = hostFromSpn(spn);
        if (!targetHost) continue;
        const targetHostId = `host-${normalizeKeyPart(targetHost)}`;
        if (!seenNodes.has(targetHostId)) {
          nodes.push({ id: targetHostId, type: 'host', label: targetHost, hostname: targetHost });
          seenNodes.add(targetHostId);
        }
        addEdgeOnce(resolvedUserId, targetHostId, 'CAN_DELEGATE_TO', 0.9, { spn });
      }
      continue;
    }

    if (objectClass.includes('group')) {
      const resolvedGroupId = groupId(sam, domain);
      if (seenNodes.has(resolvedGroupId)) continue;
      nodes.push({
        id: resolvedGroupId,
        type: 'group',
        label: sam,
        domain_name: domain,
        sid: (attrs.objectSid as string) || undefined,
        privileged: String(attrs.adminCount || '0') === '1' || undefined,
      });
      seenNodes.add(resolvedGroupId);
      continue;
    }
  }

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
