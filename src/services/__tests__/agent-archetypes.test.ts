import { describe, it, expect } from 'vitest';
import {
  allowedToolsFor,
  getArchetype,
  listArchetypes,
  isArchetypeId,
  recommendArchetype,
} from '../agent-archetypes.js';

describe('agent-archetypes: legacy role surfaces (regression-locked)', () => {
  // These three MUST stay byte-identical to the pre-registry allowedToolsFor,
  // or existing headless agents change tool surface silently.
  it('default → full overwatch surface', () => {
    expect(allowedToolsFor('default')).toBe('mcp__overwatch ToolSearch');
  });

  it('research → web + research-safe overwatch tools, no execution', () => {
    const a = allowedToolsFor('research');
    expect(a).toBe(
      'WebSearch WebFetch ToolSearch ' +
      ['get_system_prompt', 'get_agent_context', 'query_graph', 'get_skill', 'report_finding', 'research_cve', 'log_thought', 'agent_heartbeat', 'acknowledge_agent_directive', 'ask_operator', 'submit_agent_transcript', 'update_agent', 'get_evidence']
        .map(t => `mcp__overwatch__${t}`).join(' '),
    );
    expect(a).not.toContain('run_bash');
    expect(a).not.toContain('run_tool');
    expect(a).not.toContain('open_session');
  });

  it('planner → read + propose_plan only, no execution/mutation', () => {
    const a = allowedToolsFor('planner');
    expect(a).toBe(
      'ToolSearch ' +
      ['get_system_prompt', 'get_agent_context', 'query_graph', 'get_skill', 'propose_plan', 'log_thought', 'agent_heartbeat', 'acknowledge_agent_directive', 'ask_operator', 'submit_agent_transcript', 'update_agent']
        .map(t => `mcp__overwatch__${t}`).join(' '),
    );
    expect(a).not.toContain('run_bash');
    expect(a).not.toContain('report_finding');
    expect(a).not.toContain('WebSearch');
  });

  it('unknown id falls back to the full default surface', () => {
    expect(allowedToolsFor('nonsense')).toBe('mcp__overwatch ToolSearch');
    expect(allowedToolsFor(undefined)).toBe('mcp__overwatch ToolSearch');
  });
});

describe('agent-archetypes: specialized tool surfaces are real boundaries', () => {
  it('recon_scanner can execute + scope but has NO sessions or credential tools', () => {
    const a = allowedToolsFor('recon_scanner');
    expect(a).toContain('mcp__overwatch__run_bash');
    expect(a).toContain('mcp__overwatch__update_scope');
    expect(a).toContain('ToolSearch');
    expect(a).not.toContain('open_session');
    expect(a).not.toContain('expand_aws_credential');
    expect(a).not.toContain('mcp__overwatch '); // not the full-server wildcard
  });

  it('credential_operator has credential tools but no sessions', () => {
    const a = allowedToolsFor('credential_operator');
    expect(a).toContain('mcp__overwatch__validate_token_credential');
    expect(a).toContain('mcp__overwatch__expand_aws_credential');
    expect(a).not.toContain('open_session');
  });

  it('web_tester + post_exploit get sessions', () => {
    expect(allowedToolsFor('web_tester')).toContain('mcp__overwatch__open_session');
    expect(allowedToolsFor('post_exploit')).toContain('mcp__overwatch__send_to_session');
  });

  it('read-only archetypes never get target execution', () => {
    for (const id of ['pathfinder', 'report_scribe', 'cve_researcher']) {
      const a = allowedToolsFor(id);
      expect(a, id).not.toContain('mcp__overwatch__run_bash');
      expect(a, id).not.toContain('mcp__overwatch__run_tool');
      expect(a, id).not.toContain('open_session');
      // recompute_objectives persists — read-only archetypes must not have it.
      expect(a, id).not.toContain('recompute_objectives');
    }
    expect(allowedToolsFor('pathfinder')).toContain('mcp__overwatch__propose_plan');
    expect(allowedToolsFor('report_scribe')).toContain('mcp__overwatch__generate_report');
    expect(allowedToolsFor('cve_researcher')).toContain('WebSearch');
  });
});

describe('agent-archetypes: registry + recommender', () => {
  it('lists archetypes and resolves by id with a default fallback', () => {
    expect(listArchetypes().length).toBeGreaterThanOrEqual(8);
    expect(getArchetype('recon_scanner').id).toBe('recon_scanner');
    expect(getArchetype('bogus').id).toBe('default');
    expect(isArchetypeId('web_tester')).toBe(true);
    expect(isArchetypeId('nope')).toBe(false);
  });

  it('archetypes carry their legacy role bucket for prompt framing', () => {
    expect(getArchetype('cve_researcher').role).toBe('research');
    expect(getArchetype('pathfinder').role).toBe('planner');
    expect(getArchetype('recon_scanner').role).toBe('default');
  });

  it('recommends a raw IP/CIDR target as recon_scanner', () => {
    expect(recommendArchetype({ rawTarget: true })).toBe('recon_scanner');
  });

  it('mirrors the frontier→strategy intuition', () => {
    expect(recommendArchetype({ frontierType: 'network_discovery' })).toBe('recon_scanner');
    expect(recommendArchetype({ frontierType: 'credential_test' })).toBe('credential_operator');
    expect(recommendArchetype({ frontierType: 'inferred_edge' })).toBe('credential_operator');
    expect(recommendArchetype({ frontierType: 'cve_research' })).toBe('cve_researcher');
    expect(recommendArchetype({ frontierType: 'cross_tier_pivot' })).toBe('post_exploit');
    expect(recommendArchetype({ frontierType: 'incomplete_node', nodeType: 'webapp' })).toBe('web_tester');
  });

  it('recommends by node type and falls back to default', () => {
    expect(recommendArchetype({ nodeType: 'credential' })).toBe('credential_operator');
    expect(recommendArchetype({ nodeType: 'host' })).toBe('recon_scanner');
    expect(recommendArchetype({})).toBe('default');
  });
});
