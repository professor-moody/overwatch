import { describe, it, expect } from 'vitest';
import { resolve } from 'path';
import {
  allowedToolsFor,
  getArchetype,
  listArchetypes,
  isArchetypeId,
  isTargetFacing,
  recommendArchetype,
  bootstrapMission,
} from '../agent-archetypes.js';
import { SkillIndex } from '../skill-index.js';

describe('agent-archetypes: Slice 4 archetypes', () => {
  it('registers the four remaining archetypes', () => {
    for (const id of ['cloud_cartographer', 'opsec_sentinel', 'session_shepherd', 'evidence_auditor']) {
      expect(isArchetypeId(id), id).toBe(true);
    }
  });

  it('opsec_sentinel is read-only and carries get_opsec_status', () => {
    const a = allowedToolsFor('opsec_sentinel');
    expect(a).toContain('mcp__overwatch__get_opsec_status');
    expect(a).not.toContain('run_bash');
    expect(a).not.toContain('run_tool');
    expect(a).not.toContain('open_session');
  });

  it('cloud_cartographer can expand credentials and execute recon', () => {
    const a = allowedToolsFor('cloud_cartographer');
    expect(a).toContain('mcp__overwatch__expand_aws_credential');
    expect(a).toContain('mcp__overwatch__run_tool');
  });

  it('session_shepherd + evidence_auditor never get target execution', () => {
    for (const id of ['session_shepherd', 'evidence_auditor']) {
      const a = allowedToolsFor(id);
      expect(a, id).not.toContain('run_bash');
      expect(a, id).not.toContain('run_tool');
    }
    // session_shepherd reads sessions but cannot write/open them
    const ss = allowedToolsFor('session_shepherd');
    expect(ss).toContain('mcp__overwatch__list_sessions');
    expect(ss).not.toContain('mcp__overwatch__send_to_session');
  });
});

describe('agent-archetypes: skill wiring + success criteria', () => {
  // Real skills dir (vitest cwd is the repo root). Guards against defaultSkill
  // id drift — the bug this slice fixes was ids that matched no skill file.
  const skills = new SkillIndex(resolve('skills'));

  it('every archetype defaultSkill resolves to a real skill file', () => {
    for (const a of listArchetypes()) {
      if (a.defaultSkill) {
        expect(skills.getSkillContent(a.defaultSkill), `defaultSkill "${a.defaultSkill}" for archetype ${a.id}`).not.toBeNull();
      }
    }
  });

  it('every mission states a success criterion', () => {
    for (const a of listArchetypes()) {
      expect(bootstrapMission(a.id).toLowerCase(), `mission for ${a.id}`).toContain('done');
    }
  });
});

describe('agent-archetypes: bootstrap missions (per-archetype, not legacy-role)', () => {
  it('gives every archetype a non-empty mission', () => {
    for (const a of listArchetypes()) {
      expect(bootstrapMission(a.id).length).toBeGreaterThan(0);
    }
  });

  it('pathfinder analyzes attack paths (not operator-command translation like planner)', () => {
    const pf = bootstrapMission('pathfinder');
    expect(pf.toLowerCase()).toContain('attack-path');
    expect(pf).toContain('propose_plan');
    // The two must be DISTINCT — the P1 bug was pathfinder borrowing planner's brief.
    expect(pf).not.toBe(bootstrapMission('planner'));
    expect(bootstrapMission('planner').toLowerCase()).toContain('operator command');
  });

  it('report_scribe drafts via generate_report (matching its tools), not research_cve', () => {
    const rs = bootstrapMission('report_scribe');
    expect(rs).toContain('generate_report');
    expect(rs).not.toContain('research_cve');
  });

  it('recon_scanner is target-facing; cve_researcher is read-the-web only', () => {
    expect(bootstrapMission('recon_scanner')).toContain('run_tool');
    expect(bootstrapMission('cve_researcher')).toContain('research_cve');
    expect(bootstrapMission('cve_researcher')).not.toContain('run_tool');
  });

  it('the legacy research role shares the full CVE mission (auto-dispatch uses role:research)', () => {
    // The automatic CVE dispatch registers role:"research" with no archetype, so
    // it must get the same "call research_cve once / empty list marks checked"
    // brief — not a diluted one — or services never get marked checked.
    expect(bootstrapMission('research')).toBe(bootstrapMission('cve_researcher'));
    expect(bootstrapMission('research')).toContain('marked checked');
  });

  it('falls back to the default mission for an unknown id', () => {
    expect(bootstrapMission('nope')).toBe(bootstrapMission('default'));
  });
});

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

  it('osint_recon runs passive binaries (run_tool) + web, but no shell/sessions/creds', () => {
    const a = allowedToolsFor('osint_recon');
    expect(a).toContain('mcp__overwatch__run_tool');       // runs subfinder/amass/crt.sh/whois
    expect(a).toContain('mcp__overwatch__parse_output');
    expect(a).toContain('WebSearch');
    expect(a).toContain('WebFetch');
    expect(a).not.toContain('mcp__overwatch__run_bash');   // no raw shell — argv-only
    expect(a).not.toContain('open_session');               // no interactive sessions
    expect(a).not.toContain('expand_aws_credential');      // no credential tools
    // Passive recon hits public sources, not the target → not target-facing
    // (doesn't count toward per-target blast-radius caps), like cve_researcher.
    expect(isTargetFacing('osint_recon')).toBe(false);
    expect(getArchetype('osint_recon').role).toBe('research');
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
    expect(recommendArchetype({ frontierType: 'domain_enumeration' })).toBe('osint_recon');
    expect(recommendArchetype({ frontierType: 'cross_tier_pivot' })).toBe('post_exploit');
    expect(recommendArchetype({ frontierType: 'incomplete_node', nodeType: 'webapp' })).toBe('web_tester');
  });

  it('recommends by node type and falls back to default', () => {
    expect(recommendArchetype({ nodeType: 'credential' })).toBe('credential_operator');
    expect(recommendArchetype({ nodeType: 'host' })).toBe('recon_scanner');
    expect(recommendArchetype({ nodeType: 'domain' })).toBe('osint_recon');
    expect(recommendArchetype({})).toBe('default');
  });

  it('isTargetFacing splits execute archetypes from read-only ones (dispatch-cap classification)', () => {
    for (const id of ['recon_scanner', 'web_tester', 'credential_operator', 'post_exploit', 'cloud_cartographer', 'default']) {
      expect(isTargetFacing(id), id).toBe(true);
    }
    for (const id of ['pathfinder', 'report_scribe', 'opsec_sentinel', 'session_shepherd', 'evidence_auditor', 'cve_researcher', 'osint_recon', 'research', 'planner']) {
      expect(isTargetFacing(id), id).toBe(false);
    }
    // An explicit policy override defines the target-facing set by id.
    expect(isTargetFacing('pathfinder', ['pathfinder'])).toBe(true);
    expect(isTargetFacing('recon_scanner', ['pathfinder'])).toBe(false);
  });

  it('every archetype defaultSkill resolves to a real skill file', () => {
    // Locks the archetype→skill bindings: a typo, a renamed/removed skill, or a
    // mis-binding (e.g. session_shepherd→pivoting) fails here instead of silently
    // shipping an archetype whose methodology never loads into the sub-agent prompt.
    const skills = new SkillIndex(resolve('skills'));
    for (const a of listArchetypes()) {
      if (a.defaultSkill) {
        expect(skills.getSkillContent(a.defaultSkill), `${a.id} → ${a.defaultSkill}`).toBeTruthy();
      }
    }
  });
});
