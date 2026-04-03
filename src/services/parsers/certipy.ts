import type { Finding, EdgeType } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';
import { caId, certTemplateId } from '../parser-utils.js';
import { classifyPrincipalIdentity, resolveNodeIdentity } from '../identity-resolution.js';

export function parseCertipy(output: string, agentId: string = 'certipy-parser'): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const seenNodes = new Set<string>();

  // Parse certipy find output (JSON format)
  try {
    const data = JSON.parse(output);

    // Certificate Authorities
    if (data['Certificate Authorities']) {
      for (const [caName, caData] of Object.entries(data['Certificate Authorities'] as Record<string, any>)) {
        const caNodeId = caId(caName);
        if (!seenNodes.has(caNodeId)) {
          nodes.push({
            id: caNodeId,
            type: 'ca',
            label: caName,
            ca_name: caName,
            ca_kind: 'enterprise_ca',
          });
          seenNodes.add(caNodeId);
        }
      }
    }

    // Certificate Templates
    if (data['Certificate Templates']) {
      for (const [templateName, templateData] of Object.entries(data['Certificate Templates'] as Record<string, any>)) {
        const tmplId = certTemplateId(templateName);
        const tmpl = templateData as Record<string, any>;

        if (!seenNodes.has(tmplId)) {
          nodes.push({
            id: tmplId,
            type: 'cert_template',
            label: templateName,
            template_name: templateName,
            enrollee_supplies_subject: tmpl['Enrollee Supplies Subject'] === true,
            eku: Array.isArray(tmpl['Extended Key Usage']) ? tmpl['Extended Key Usage'] : undefined,
          });
          seenNodes.add(tmplId);
        }

        // Check for ESC vulnerabilities
        if (tmpl['[!] Vulnerabilities']) {
          const vulns = tmpl['[!] Vulnerabilities'] as Record<string, any>;
          for (const [escName] of Object.entries(vulns)) {
            const escType = escName.toUpperCase().replace(/[^A-Z0-9]/g, '') as EdgeType;
            if (['ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC6', 'ESC8'].includes(escType)) {
              // Create ESC edge from enrollable entities to template
              if (tmpl['Enrollment Permissions'] && tmpl['Enrollment Permissions']['Enrollment Rights']) {
                for (const principal of tmpl['Enrollment Permissions']['Enrollment Rights'] as string[]) {
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
                  edges.push({
                    source: resolvedPrincipalId,
                    target: tmplId,
                    properties: {
                      type: escType as EdgeType,
                      confidence: 0.9,
                      discovered_at: new Date().toISOString(),
                      discovered_by: agentId,
                    },
                  });
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
