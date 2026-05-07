import type { Finding, EdgeType } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { caId, certTemplateId, domainId } from '../parser-utils.js';
import { classifyPrincipalIdentity, resolveNodeIdentity } from '../identity-resolution.js';

function readFirst(obj: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys) {
    if (obj[key] !== undefined) return obj[key];
  }
  return undefined;
}

function parseBool(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (['true', 'yes', 'enabled', 'enable', 'on', '1', 'set'].includes(normalized)) return true;
  if (['false', 'no', 'disabled', 'disable', 'off', '0', 'unset'].includes(normalized)) return false;
  return undefined;
}

function parseNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function parseStringArray(value: unknown): string[] | undefined {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === 'string' && value.trim()) {
    return value.split(/[,;]/).map(v => v.trim()).filter(Boolean);
  }
  return undefined;
}

export function parseCertipy(output: string, agentId: string = 'certipy-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();
  const seenEdges = new Set<string>();

  function addEdge(source: string, target: string, type: EdgeType, confidence: number = 1.0) {
    const key = `${source}->${target}:${type}`;
    if (seenEdges.has(key)) return;
    seenEdges.add(key);
    edges.push({
      source,
      target,
      properties: {
        type,
        confidence,
        discovered_at: new Date().toISOString(),
        discovered_by: agentId,
      },
    });
  }

  // P2.3: collect CA-level findings (ESC6/ESC8/ESC11/etc.) so they can be
  // expanded into principal→ca vulnerability edges after enrollment perms
  // are known. Previously the parser only inspected template-level
  // vulnerabilities and missed every ESC path tied to a CA flag (SAN abuse,
  // unauthenticated HTTP enrollment, missing ICPR encryption).
  const caEscFindings = new Map<string, Set<string>>(); // caNodeId -> set of ESC ids ('ESC6', 'ESC8', ...)
  const caEscFromCondition = (caId: string, esc: string) => {
    const existing = caEscFindings.get(caId) || new Set<string>();
    existing.add(esc);
    caEscFindings.set(caId, existing);
  };

  // Parse certipy find output (JSON format)
  try {
    const data = JSON.parse(output);

    // Build CA → templates mapping from CA data
    const caTemplateMap = new Map<string, string[]>();

    // Certificate Authorities
    if (data['Certificate Authorities']) {
      for (const [caName, caData] of Object.entries(data['Certificate Authorities'] as Record<string, unknown>)) {
        const caNodeId = caId(caName);
        const ca = caData as Record<string, unknown>;
        if (!seenNodes.has(caNodeId)) {
          const enforceEncrypt = parseBool(readFirst(ca, [
            'IF_ENFORCEENCRYPTICERTREQUEST',
            'Enforce Encryption for Requests',
            'Enforce Encryption for Requests?',
          ]));
          const sanFlag = parseBool(readFirst(ca, [
            'EDITF_ATTRIBUTESUBJECTALTNAME2',
            'User Specified SAN',
            'User Specified SAN?',
            'Request Disposition - User Specified SAN',
          ]));
          const httpEnrollment = parseBool(readFirst(ca, [
            'Web Enrollment',
            'Web Enrollment Enabled',
            'HTTP Enrollment',
            'HTTP Enrollment Enabled',
            'Enrollment Web Service',
          ]));
          const strongBinding = parseNumber(readFirst(ca, [
            'StrongCertificateBindingEnforcement',
            'Strong Certificate Binding Enforcement',
          ]));
          const mappingMethods = parseStringArray(readFirst(ca, [
            'CertificateMappingMethods',
            'Certificate Mapping Methods',
          ]));
          nodes.push({
            id: caNodeId,
            type: 'ca',
            label: caName,
            ca_name: caName,
            ca_kind: 'enterprise_ca',
            ...(enforceEncrypt !== undefined ? { enforce_encrypt_icert_request: enforceEncrypt } : {}),
            ...(sanFlag !== undefined ? { san_flag_enabled: sanFlag } : {}),
            ...(httpEnrollment !== undefined ? { http_enrollment: httpEnrollment } : {}),
            ...(strongBinding !== undefined ? { strong_cert_binding_enforcement: strongBinding } : {}),
            ...(mappingMethods ? { certificate_mapping_methods: mappingMethods } : {}),
          });
          seenNodes.add(caNodeId);
        }

        // P2.3: derive CA-level ESC findings from CA flags. These become
        // principal→ca edges below once enrollment rights are known.
        const enforceEncryptVal = parseBool(readFirst(ca, [
          'IF_ENFORCEENCRYPTICERTREQUEST',
          'Enforce Encryption for Requests',
          'Enforce Encryption for Requests?',
        ]));
        const sanFlagVal = parseBool(readFirst(ca, [
          'EDITF_ATTRIBUTESUBJECTALTNAME2',
          'User Specified SAN',
          'User Specified SAN?',
          'Request Disposition - User Specified SAN',
        ]));
        const httpEnrollmentVal = parseBool(readFirst(ca, [
          'Web Enrollment',
          'Web Enrollment Enabled',
          'HTTP Enrollment',
          'HTTP Enrollment Enabled',
          'Enrollment Web Service',
        ]));
        // ESC6 — `EDITF_ATTRIBUTESUBJECTALTNAME2` (User Specified SAN) lets
        // any enrollee request a cert for an arbitrary UPN/SAN, regardless
        // of the template. Affects every principal who can enroll any
        // template offered by this CA.
        if (sanFlagVal === true) caEscFromCondition(caNodeId, 'ESC6');
        // ESC8 — HTTP/web enrollment endpoint enabled and enrollment
        // requests aren't encrypted (so NTLM relay against the endpoint
        // works). Conservative trigger: HTTP enrollment on + enforce_encrypt
        // not affirmatively true.
        if (httpEnrollmentVal === true && enforceEncryptVal !== true) {
          caEscFromCondition(caNodeId, 'ESC8');
        }
        // CA-level vulnerability block (Certipy may report ESCs under the
        // CA itself for things like ESC6/ESC8/ESC11). Keep this on top of
        // flag-derived findings so explicit Certipy assertions survive.
        const caVulns = ca['[!] Vulnerabilities'] as Record<string, unknown> | undefined;
        if (caVulns) {
          for (const escName of Object.keys(caVulns)) {
            const escType = escName.toUpperCase().replace(/[^A-Z0-9]/g, '');
            if (['ESC5', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC12'].includes(escType)) {
              caEscFromCondition(caNodeId, escType);
            }
          }
        }

        // Extract domain from DNS Name (e.g., "dc01.acme.corp" → "acme.corp")
        const dnsName = ca['DNS Name'] as string | undefined;
        if (dnsName) {
          const parts = dnsName.split('.');
          if (parts.length >= 2) {
            const domainName = parts.slice(1).join('.');
            const domainNodeId = domainId(domainName);
            if (!seenNodes.has(domainNodeId)) {
              nodes.push({ id: domainNodeId, type: 'domain', label: domainName, domain_name: domainName });
              seenNodes.add(domainNodeId);
            }
            addEdge(domainNodeId, caNodeId, 'OPERATES_CA');
          }
        }

        // Track which templates this CA offers. parseStringArray accepts
        // both array and single-string shapes; a comma/semicolon-separated
        // string is split. Without this, a stringified template list would
        // silently leave the CA→template map empty and ISSUED_BY edges
        // would never be created.
        const caTemplates = parseStringArray(ca['Certificate Templates']);
        if (caTemplates && caTemplates.length > 0) {
          caTemplateMap.set(caNodeId, caTemplates);
        }
      }
    }

    // Certificate Templates
    if (data['Certificate Templates']) {
      for (const [templateName, templateData] of Object.entries(data['Certificate Templates'] as Record<string, unknown>)) {
        const tmplId = certTemplateId(templateName);
        const tmpl = templateData as Record<string, unknown>;

        if (!seenNodes.has(tmplId)) {
          // Extract ESC9/13-relevant properties
          const msPkiCertNameFlag = tmpl['msPKI-Certificate-Name-Flag'] as number | undefined;
          const ctFlagNoSecExt = msPkiCertNameFlag !== undefined
            ? (msPkiCertNameFlag & 0x00080000) !== 0  // CT_FLAG_NO_SECURITY_EXTENSION = 0x80000
            : undefined;
          // Certipy may also report this directly in vulnerabilities
          const vulns = tmpl['[!] Vulnerabilities'] as Record<string, unknown> | undefined;
          const hasEsc9 = vulns?.['ESC9'] !== undefined;
          const hasEsc13 = vulns?.['ESC13'] !== undefined;

          // Issuance policy (ESC13)
          const issuancePolicy = tmpl['Issuance Policies'] as Record<string, unknown> | undefined;
          const policyOid = tmpl['msPKI-Certificate-Policy'] as string
            || (issuancePolicy ? Object.keys(issuancePolicy)[0] : undefined);
          const policyGroupLink = issuancePolicy
            ? (Object.values(issuancePolicy)[0] as Record<string, unknown> | undefined)?.['Linked Group'] as string | undefined
            : undefined;

          nodes.push({
            id: tmplId,
            type: 'cert_template',
            label: templateName,
            template_name: templateName,
            // Phase J: tolerate both boolean and string ("true"/"yes"/"enabled")
            // shapes for these fields. Older Certipy versions (and some JSON
            // post-processors) emit them as strings instead of booleans.
            enrollee_supplies_subject: parseBool(tmpl['Enrollee Supplies Subject']),
            // EKU may arrive as an array OR a single string (one EKU). Coerce
            // both shapes through parseStringArray so the cert_template node
            // always carries a string[] (or undefined when absent).
            eku: parseStringArray(tmpl['Extended Key Usage']),
            ...(ctFlagNoSecExt !== undefined ? { ct_flag_no_security_extension: ctFlagNoSecExt } : {}),
            ...(hasEsc9 && ctFlagNoSecExt === undefined ? { ct_flag_no_security_extension: true } : {}),
            ...(policyOid ? { issuance_policy_oid: policyOid } : {}),
            ...(policyGroupLink ? { issuance_policy_group_link: policyGroupLink } : {}),
            ...(hasEsc13 && !policyOid ? { issuance_policy_oid: 'unknown' } : {}),
          });
          seenNodes.add(tmplId);
        }

        // ISSUED_BY: link template to the CA(s) that offer it
        for (const [caNodeId, templates] of caTemplateMap) {
          if (templates.some(t => t.toLowerCase() === templateName.toLowerCase())) {
            addEdge(tmplId, caNodeId, 'ISSUED_BY');
          }
        }

        // CAN_ENROLL: create for all enrollment rights (not gated by vulnerabilities).
        //
        // `Enrollment Rights` can arrive as either an array (typical Certipy
        // JSON) or a single string (when a JSON post-processor flattens a
        // 1-element list, or when a downstream tool emits comma-separated
        // text). Casting to `string[]` blindly turned the latter into a
        // for-of over individual characters, fabricating one bogus principal
        // node per letter. parseStringArray handles both shapes the same
        // way it does for `Extended Key Usage` above.
        const enrollPerms = tmpl['Enrollment Permissions'] as Record<string, unknown> | undefined;
        const enrollRights = parseStringArray(enrollPerms?.['Enrollment Rights']);
        if (enrollRights) {
          for (const principal of enrollRights) {
            const principalIdentity = classifyPrincipalIdentity(principal);
            const principalId = principalIdentity.id;
            const resolution = resolveNodeIdentity({
              id: principalId,
              type: principalIdentity.nodeType,
              label: principalIdentity.label,
              username: principalIdentity.username,
              domain_name: principalIdentity.domain_name,
            });
            const resolvedPrincipalId = resolution.id;
            if (!seenNodes.has(resolvedPrincipalId)) {
              nodes.push({
                id: resolvedPrincipalId,
                type: principalIdentity.nodeType,
                label: principalIdentity.label,
                username: principalIdentity.username,
                domain_name: principalIdentity.domain_name,
                identity_status: resolution.status,
                identity_family: resolution.family,
                canonical_id: resolution.status === 'canonical' ? resolvedPrincipalId : undefined,
                identity_markers: resolution.markers,
                principal_type_ambiguous: principalIdentity.ambiguous || undefined,
              });
              seenNodes.add(resolvedPrincipalId);
            }

            addEdge(resolvedPrincipalId, tmplId, 'CAN_ENROLL', 1.0);

            // ESC vulnerability edges (on top of enrollment)
            if (tmpl['[!] Vulnerabilities']) {
              const vulns = tmpl['[!] Vulnerabilities'] as Record<string, unknown>;
              for (const [escName] of Object.entries(vulns)) {
                const escType = escName.toUpperCase().replace(/[^A-Z0-9]/g, '') as EdgeType;
                if (['ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC7', 'ESC8', 'ESC9', 'ESC10', 'ESC11', 'ESC12', 'ESC13'].includes(escType)) {
                  addEdge(resolvedPrincipalId, tmplId, escType, 0.9);
                }
              }
            }

            // P2.3: CA-level ESC findings expand to principal→ca edges for
            // every principal who can enroll any template offered by this
            // CA. Schema constrains ESC6/ESC7/ESC8/ESC11/ESC12 to target a
            // CA node, so this is the right destination.
            for (const [caNodeId, caTemplates] of caTemplateMap) {
              const offersThisTemplate = caTemplates.some(t => t.toLowerCase() === templateName.toLowerCase());
              if (!offersThisTemplate) continue;
              const caEscs = caEscFindings.get(caNodeId);
              if (!caEscs) continue;
              for (const esc of caEscs) {
                if (['ESC5', 'ESC6', 'ESC7', 'ESC8', 'ESC11', 'ESC12'].includes(esc)) {
                  addEdge(resolvedPrincipalId, caNodeId, esc as EdgeType, 0.9);
                }
              }
            }
          }
        }
      }
    }
  } catch {
    // Not JSON — try line-based parsing for certipy text output
    const lines = output.split('\n');
    for (const line of lines) {
      const templateMatch = line.match(/Template Name\s*:\s*(.+)/i);
      if (templateMatch) {
        const templateName = templateMatch[1].trim();
        const tmplId = certTemplateId(templateName);
        if (!seenNodes.has(tmplId)) {
          nodes.push({
            id: tmplId,
            type: 'cert_template',
            label: templateName,
            template_name: templateName,
          });
          seenNodes.add(tmplId);
        }
      }
    }
  }

  return {
    id: uuidv4(),
    agent_id: agentId,
    timestamp: new Date().toISOString(),
    nodes,
    edges,
  };
}
