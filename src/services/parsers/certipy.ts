import type { Finding, EdgeType } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { caId, certTemplateId, domainId } from '../parser-utils.js';
import { classifyPrincipalIdentity, resolveNodeIdentity } from '../identity-resolution.js';

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
          const enforceEncrypt = ca['IF_ENFORCEENCRYPTICERTREQUEST'] ?? ca['Enforce Encryption for Requests'];
          nodes.push({
            id: caNodeId,
            type: 'ca',
            label: caName,
            ca_name: caName,
            ca_kind: 'enterprise_ca',
            ...(enforceEncrypt === false || enforceEncrypt === 'Disabled'
              ? { enforce_encrypt_icert_request: false }
              : enforceEncrypt === true || enforceEncrypt === 'Enabled'
                ? { enforce_encrypt_icert_request: true }
                : {}),
          });
          seenNodes.add(caNodeId);
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

        // Track which templates this CA offers
        const caTemplates = ca['Certificate Templates'] as string[] | undefined;
        if (Array.isArray(caTemplates)) {
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
            enrollee_supplies_subject: tmpl['Enrollee Supplies Subject'] === true,
            eku: Array.isArray(tmpl['Extended Key Usage']) ? tmpl['Extended Key Usage'] : undefined,
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

        // CAN_ENROLL: create for all enrollment rights (not gated by vulnerabilities)
        const enrollPerms = tmpl['Enrollment Permissions'] as Record<string, unknown> | undefined;
        const enrollRights = enrollPerms?.['Enrollment Rights'] as string[] | undefined;
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
