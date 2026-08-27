import type { EvidenceChainResponse, ExportedGraph, ExportedNode, FindingContextResponse, ProofExcerpt } from './types';
import type { FindingDto } from './api';
import { resolveAssetToNodeId } from './relationships';
import { findingTitle } from './finding-display';

function clean(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

export function resolveEvidenceQuery(query: string, graph: ExportedGraph, findings: FindingDto[] = []): string | null {
  const q = query.trim();
  if (!q) return null;
  const lower = q.toLowerCase();

  for (const node of graph.nodes) {
    const values = [
      node.id,
      node.label,
      node.hostname,
      node.ip,
      node.username,
      node.domain,
      node.url,
      node.arn,
      node.provider_resource_id,
      node.cred_user,
    ].map(clean).filter((value): value is string => !!value);
    if (values.some(value => value.toLowerCase() === lower)) return node.id;
  }

  for (const finding of findings) {
    if (finding.id.toLowerCase() === lower || finding.title.toLowerCase() === lower || findingTitle(finding).toLowerCase() === lower) {
      for (const asset of finding.affected_assets) {
        const nodeId = resolveAssetToNodeId(asset, graph);
        if (nodeId) return nodeId;
      }
    }
    for (const asset of finding.affected_assets) {
      if (asset.toLowerCase() === lower) {
        const nodeId = resolveAssetToNodeId(asset, graph);
        if (nodeId) return nodeId;
      }
    }
  }

  return null;
}

export interface EvidenceNarrativeItem {
  id: string;
  node_id: string;
  label: string;
  count: number;
  latest?: string;
  description?: string;
  proof?: string;
  /** The exact command that produced this evidence - the "how it was found". */
  command?: string;
  /** The agent/sub-agent that ran it. */
  agent_id?: string;
  /** Honesty label: observed (direct capture) / asserted (claimed) / inferred (rule). */
  source_trust?: 'observed' | 'asserted' | 'inferred';
  /** Exit code of the producing command, when it was a real execution. */
  exit_code?: number;
  /** SHA-256 of the captured blob - tamper-evident proof handle. */
  content_hash?: string;
  evidence_id?: string;
  /** Matched-signal excerpts: the specific bytes that justify the finding, re-read and
   *  verified against the evidence blob. */
  excerpts?: ProofExcerpt[];
  source_kind: 'command_output' | 'parsed_result' | 'activity';
  event_type?: string;
  action_id?: string;
  tool?: string;
}

export function narrativeItemsFromChains(chains: EvidenceChainResponse[]): EvidenceNarrativeItem[] {
  return chains.map(chain => {
    const first = chain.chains[0];
    const findingDescription = chain.findings?.[0]?.description;
    const snippet = first?.snippet || first?.description || findingDescription;
    // The exact command + the acting agent can live on different lifecycle entries of
    // the same chain (validate → run → complete → parse), so lift each from the entry
    // that actually carries it. The old mapping read only chains[0] and dropped both,
    // so "how it was found" was invisible even though the data was here all along.
    const command = chain.chains.find(entry => entry.command)?.command;
    const agent_id = chain.chains.find(entry => entry.agent_id)?.agent_id;
    // The proof fields (excerpts / source_trust / exit code / hash) travel together on a
    // per-action chain, so lift them from the primary proof entry - the one with matched
    // excerpts, else the command entry, else the first - rather than mixing across entries.
    const proof = chain.chains.find(entry => entry.excerpts?.length)
      ?? chain.chains.find(entry => entry.command)
      ?? first;
    return {
      id: chain.node_id,
      node_id: chain.node_id,
      label: chain.node_props?.label || chain.node_id,
      count: chain.count,
      latest: first?.timestamp,
      description: findingDescription || first?.description,
      proof: snippet,
      command,
      agent_id,
      source_trust: proof?.source_trust,
      exit_code: proof?.exit_code,
      content_hash: proof?.content_hash,
      evidence_id: proof?.evidence_id,
      excerpts: proof?.excerpts,
      source_kind: command ? 'command_output' : sourceKindForChain(first),
      event_type: first?.event_type,
      action_id: first?.action_id,
      tool: first?.tool,
    };
  });
}

function sourceKindForChain(entry: EvidenceChainResponse['chains'][number] | undefined): EvidenceNarrativeItem['source_kind'] {
  if (!entry) return 'activity';
  if (entry.tool || entry.command) return 'command_output';
  if (/parsed|ingest|finding/i.test(entry.event_type || '')) return 'parsed_result';
  return 'activity';
}

export function narrativeItemsFromFindingContext(context: FindingContextResponse | null): EvidenceNarrativeItem[] {
  if (!context) return [];
  return narrativeItemsFromChains(context.evidence_chains);
}

export function findingAffectedNodeIds(finding: FindingDto, graph: ExportedGraph): string[] {
  return [...new Set(finding.affected_assets.map(asset => resolveAssetToNodeId(asset, graph)).filter((value): value is string => !!value))];
}

export function nodeLabel(node: ExportedNode | undefined, fallback: string): string {
  return clean(node?.label) || fallback;
}
