// ============================================================
// Imperative Inference Handlers
// Inference rules that require graph traversal beyond the
// selector-based InferenceEngine pattern.
// ============================================================

import type { EngineContext, ActivityLogEntry } from './engine-context.js';
import type { NodeProperties, EdgeProperties, NodeType } from '../types.js';
import { isIpInCidr } from './cidr.js';
import { isCredentialStaleOrExpired } from './credential-utils.js';

export interface ImperativeInferenceHost {
  ctx: EngineContext;
  addNode(props: NodeProperties): string;
  addEdge(source: string, target: string, props: EdgeProperties): { id: string; isNew: boolean };
  getNode(id: string): NodeProperties | null;
  log(message: string, agentId?: string, extra?: Partial<ActivityLogEntry>): void;
  invalidateHealthReport(): void;
}

const CMS_DEFAULT_CREDS: Record<string, { user: string; type: string }> = {
  wordpress: { user: 'admin', type: 'plaintext' },
  tomcat: { user: 'tomcat', type: 'plaintext' },
  jenkins: { user: 'admin', type: 'plaintext' },
  grafana: { user: 'admin', type: 'plaintext' },
  phpmyadmin: { user: 'root', type: 'plaintext' },
};

export function inferPivotReachability(host: ImperativeInferenceHost, triggerHostId: string): string[] {
  const inferred: string[] = [];
  const hostNode = host.getNode(triggerHostId);
  if (!hostNode || hostNode.type !== 'host' || !hostNode.ip) return inferred;

  const sessionHolders: string[] = [];
  for (const edge of host.ctx.graph.inEdges(triggerHostId) as string[]) {
    const attrs = host.ctx.graph.getEdgeAttributes(edge);
    if (attrs.type === 'HAS_SESSION' && attrs.confidence >= 0.9) {
      sessionHolders.push(host.ctx.graph.source(edge));
    }
  }
  if (sessionHolders.length === 0) return inferred;

  const matchingSubnets: string[] = [];
  host.ctx.graph.forEachNode((nodeId: string, attrs) => {
    if (attrs.type === 'subnet' && attrs.subnet_cidr && isIpInCidr(hostNode.ip!, attrs.subnet_cidr)) {
      matchingSubnets.push(nodeId);
    }
  });
  if (matchingSubnets.length === 0) return inferred;

  const now = new Date().toISOString();
  for (const subnetId of matchingSubnets) {
    const subnetCidr = host.ctx.graph.getNodeAttributes(subnetId).subnet_cidr as string;

    const coldPeersToPromote: string[] = [];
    host.ctx.coldStore.forEach((record) => {
      if (!record.ip || record.id === triggerHostId) return;
      if (isIpInCidr(record.ip, subnetCidr)) coldPeersToPromote.push(record.id);
    });
    for (const coldPeerId of coldPeersToPromote) {
      const coldRecord = host.ctx.coldStore.promote(coldPeerId);
      if (coldRecord) {
        host.addNode({
          id: coldRecord.id,
          type: coldRecord.type as NodeType,
          label: coldRecord.label,
          ip: coldRecord.ip,
          hostname: coldRecord.hostname,
          discovered_at: coldRecord.discovered_at,
          last_seen_at: coldRecord.last_seen_at,
          alive: coldRecord.alive,
          discovered_by: coldRecord.provenance,
          confidence: 1.0,
        });
      }
    }

    host.ctx.graph.forEachNode((peerId: string, peerAttrs) => {
      if (peerId === triggerHostId) return;
      if (peerAttrs.type !== 'host' || !peerAttrs.ip) return;
      if (!isIpInCidr(peerAttrs.ip, subnetCidr)) return;

      const existing = host.ctx.graph.edges(triggerHostId, peerId);
      if (existing.some((e: string) => host.ctx.graph.getEdgeAttributes(e).type === 'REACHABLE')) return;

      const { id: edgeId } = host.addEdge(triggerHostId, peerId, {
        type: 'REACHABLE',
        confidence: 0.6,
        discovered_at: now,
        discovered_by: 'inference:pivot-reachability',
        tested: false,
        inferred_by_rule: 'pivot-reachability',
        inferred_at: now,
        via_pivot: sessionHolders[0],
      });
      inferred.push(edgeId);
      host.log(`Inferred pivot reachability: ${triggerHostId} → ${peerId} via ${sessionHolders[0]}`, undefined, {
        category: 'inference',
        event_type: 'inference_generated',
      });
    });
  }
  return inferred;
}

export function inferDefaultCredentials(host: ImperativeInferenceHost, webappNodeIds: Set<string>): string[] {
  const inferred: string[] = [];
  const now = new Date().toISOString();

  for (const nodeId of webappNodeIds) {
    if (!host.ctx.graph.hasNode(nodeId)) continue;
    const attrs = host.ctx.graph.getNodeAttributes(nodeId);
    if (attrs.type !== 'webapp' || !attrs.cms_type) continue;

    const cmsKey = (attrs.cms_type as string).toLowerCase();
    const defaults = CMS_DEFAULT_CREDS[cmsKey];
    if (!defaults) continue;

    const credId = `cred-default-${cmsKey}`;

    if (!host.ctx.graph.hasNode(credId)) {
      host.addNode({
        id: credId,
        type: 'credential',
        label: `Default ${cmsKey} credential (${defaults.user})`,
        discovered_at: now,
        discovered_by: 'inference:default-creds',
        confidence: 0.3,
        cred_type: 'plaintext',
        cred_user: defaults.user,
        cred_material_kind: 'plaintext_password',
        cred_usable_for_auth: true,
        cred_evidence_kind: 'manual',
        cred_is_default_guess: true,
        credential_status: 'active',
      });
    }

    const existing = host.ctx.graph.edges(credId, nodeId);
    if (existing.some((e: string) => host.ctx.graph.getEdgeAttributes(e).type === 'POTENTIAL_AUTH')) continue;

    const { id: edgeId } = host.addEdge(credId, nodeId, {
      type: 'POTENTIAL_AUTH',
      confidence: 0.3,
      discovered_at: now,
      discovered_by: 'inference:default-creds',
      tested: false,
      inferred_by_rule: 'default-creds',
      inferred_at: now,
    });
    inferred.push(edgeId);
    host.log(`Inferred default credentials for ${cmsKey} webapp: ${credId} → ${nodeId}`, undefined, {
      category: 'inference',
      event_type: 'inference_generated',
    });
  }

  return inferred;
}

export function inferImdsv1Ssrf(host: ImperativeInferenceHost, webappNodeIds: Set<string>): string[] {
  const inferred: string[] = [];
  const now = new Date().toISOString();

  for (const webappId of webappNodeIds) {
    if (!host.ctx.graph.hasNode(webappId)) continue;
    const vulnEdges = (host.ctx.graph.outEdges(webappId) as string[]).filter(e =>
      host.ctx.graph.getEdgeAttributes(e).type === 'VULNERABLE_TO'
    );
    const ssrfVulns = vulnEdges.map(e => host.ctx.graph.target(e)).filter(vId => {
      const v = host.ctx.graph.getNodeAttributes(vId);
      return v.vuln_type === 'ssrf';
    });
    if (ssrfVulns.length === 0) continue;

    const hostingServices: string[] = [];
    host.ctx.graph.forEachInEdge(webappId, (_e: string, attrs, src: string) => {
      if (attrs.type === 'HOSTS') hostingServices.push(src);
    });

    for (const svcId of hostingServices) {
      const hostIds: string[] = [];
      host.ctx.graph.forEachInEdge(svcId, (_e: string, attrs, src: string) => {
        if (attrs.type === 'RUNS') hostIds.push(src);
      });

      for (const hostId of hostIds) {
        host.ctx.graph.forEachOutEdge(hostId, (_e: string, attrs, _src: string, tgt: string) => {
          if (attrs.type !== 'RUNS_ON') return;
          const cr = host.ctx.graph.getNodeAttributes(tgt);
          if (cr.type !== 'cloud_resource' || cr.resource_type !== 'ec2') return;
          if (cr.imdsv2_required === true) return;

          host.ctx.graph.forEachOutEdge(tgt, (_e2: string, a2, _s2: string, identityId: string) => {
            if (a2.type !== 'MANAGED_BY') return;
            for (const vulnId of ssrfVulns) {
              const existing = host.ctx.graph.edges(vulnId, identityId);
              if (existing.some((ex: string) => host.ctx.graph.getEdgeAttributes(ex).type === 'EXPLOITS')) return;

              const { id: edgeId } = host.addEdge(vulnId, identityId, {
                type: 'EXPLOITS',
                confidence: 0.85,
                discovered_at: now,
                discovered_by: 'inference:imdsv1-ssrf',
                tested: false,
                inferred_by_rule: 'imdsv1-ssrf',
                inferred_at: now,
              });
              inferred.push(edgeId);
              host.log(`Inferred SSRF→IMDS credential capture: ${vulnId} → ${identityId}`, undefined, {
                category: 'inference', event_type: 'inference_generated',
              });
            }
          });
        });
      }
    }
  }
  return inferred;
}

export function inferManagedIdentityPivot(host: ImperativeInferenceHost, hostNodeIds: Set<string>): string[] {
  const inferred: string[] = [];
  const now = new Date().toISOString();

  for (const hostId of hostNodeIds) {
    if (!host.ctx.graph.hasNode(hostId)) continue;
    const hostAttrs = host.ctx.graph.getNodeAttributes(hostId);
    if (hostAttrs.type !== 'host') continue;

    const sessionHolders: string[] = [];
    host.ctx.graph.forEachInEdge(hostId, (_e: string, attrs, src: string) => {
      if (attrs.type === 'HAS_SESSION' && attrs.confidence >= 0.9) sessionHolders.push(src);
    });
    if (sessionHolders.length === 0) continue;

    host.ctx.graph.forEachOutEdge(hostId, (_e: string, attrs, _src: string, crId: string) => {
      if (attrs.type !== 'RUNS_ON') return;
      host.ctx.graph.forEachOutEdge(crId, (_e2: string, a2, _s2: string, identityId: string) => {
        if (a2.type !== 'MANAGED_BY') return;

        for (const holder of sessionHolders) {
          const existing = host.ctx.graph.edges(holder, identityId);
          if (existing.some((ex: string) => host.ctx.graph.getEdgeAttributes(ex).type === 'POTENTIAL_AUTH')) continue;

          const { id: edgeId } = host.addEdge(holder, identityId, {
            type: 'POTENTIAL_AUTH',
            confidence: 0.75,
            discovered_at: now,
            discovered_by: 'inference:managed-identity-pivot',
            tested: false,
            inferred_by_rule: 'managed-identity-pivot',
            inferred_at: now,
          });
          inferred.push(edgeId);
          host.log(`Inferred managed identity pivot: ${holder} → ${identityId} via ${crId}`, undefined, {
            category: 'inference', event_type: 'inference_generated',
          });
        }
      });
    });
  }
  return inferred;
}

export function degradeExpiredCredentialEdges(host: ImperativeInferenceHost, credNodeId: string): string[] {
  const node = host.getNode(credNodeId);
  if (!node || node.type !== 'credential' || !isCredentialStaleOrExpired(node)) return [];

  const degraded: string[] = [];
  for (const edgeId of host.ctx.graph.outEdges(credNodeId) as string[]) {
    const attrs = host.ctx.graph.getEdgeAttributes(edgeId);
    if (attrs.type !== 'POTENTIAL_AUTH') continue;
    const newConfidence = Math.max(0.1, attrs.confidence * 0.5);
    if (newConfidence >= attrs.confidence) continue;
    host.ctx.graph.mergeEdgeAttributes(edgeId, { confidence: newConfidence } as Partial<EdgeProperties>);
    degraded.push(edgeId);
  }

  if (degraded.length > 0) {
    host.log(`Degraded ${degraded.length} POTENTIAL_AUTH edge(s) from expired/stale credential ${credNodeId}`, undefined, {
      category: 'inference',
      event_type: 'credential_degradation',
      details: { credential_node: credNodeId, degraded_edges: degraded.length, credential_status: node.credential_status },
    });
    host.invalidateHealthReport();
  }

  return degraded;
}
