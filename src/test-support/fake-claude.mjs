#!/usr/bin/env node
// ============================================================
// Fake `claude` CLI for headless-runner integration tests.
//
// Stands in for `claude -p ...`: reads the --mcp-config the runner wrote,
// connects to the Overwatch HTTP MCP endpoint as a real MCP client, exercises
// the sub-agent loop (get_agent_context → report_finding → update_agent), and
// emits a couple of stream-json lines. Behavior is selected by env:
//   OVERWATCH_FAKE_MODE = 'complete' (default) | 'hang' | 'research' | 'planner' | 'ask'
//   OVERWATCH_TASK_ID   = the agent task id (set by the runner)
// ============================================================
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

function emit(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }

function argValue(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const mode = process.env.OVERWATCH_FAKE_MODE || 'complete';
  const taskId = process.env.OVERWATCH_TASK_ID;
  const cfgPath = argValue('--mcp-config');
  const cfg = JSON.parse(readFileSync(cfgPath, 'utf-8'));
  const server = cfg.mcpServers.overwatch;
  const headers = server.headers || undefined;

  const transport = new StreamableHTTPClientTransport(new URL(server.url), {
    requestInit: headers ? { headers } : undefined,
  });
  const client = new Client({ name: 'fake-claude', version: '0.0.0' });
  await client.connect(transport);
  emit({ type: 'system', subtype: 'init', task_id: taskId, mode });

  // Discover scope + agent identity + (for the 'auto' orchestration-child mode)
  // this child's archetype, so it can land type-appropriate findings.
  let agentId = 'fake-agent';
  let childArchetype = '';
  let frontierItemId = '';
  try {
    const contextRequest = { name: 'get_agent_context', arguments: { task_id: taskId } };
    if (mode === 'hermetic-recon') {
      emit({ type: 'tool_use', name: 'mcp__overwatch__get_agent_context', input: contextRequest.arguments });
    }
    const ctx = await client.callTool(contextRequest);
    const parsed = JSON.parse(ctx.content[0].text);
    if (parsed.agent_id) agentId = parsed.agent_id;
    if (parsed.archetype) childArchetype = parsed.archetype;
    if (parsed.frontier_item_id) frontierItemId = parsed.frontier_item_id;
  } catch { /* context optional for the fake */ }

  if (mode === 'hermetic-recon') {
    if (!frontierItemId) throw new Error('hermetic recon context did not include frontier_item_id');
    const actionId = `eval-recon-nmap-${taskId}`;
    const validationInput = {
      action_id: actionId,
      frontier_item_id: frontierItemId,
      target_ip: '10.10.10.10',
      technique: 'service_enumeration',
      tool_name: 'nmap',
      description: 'Hermetic nmap service enumeration of 10.10.10.10',
    };
    emit({ type: 'tool_use', name: 'mcp__overwatch__validate_action', input: validationInput });
    const validation = await client.callTool({ name: 'validate_action', arguments: validationInput });
    const validationPayload = JSON.parse(validation.content[0].text);
    if (validationPayload.validation_result === 'invalid') {
      throw new Error(`hermetic recon validation failed: ${validation.content[0].text}`);
    }

    const runInput = {
      binary: 'nmap',
      args: ['-sV', '-oX', '-', '10.10.10.10'],
      action_id: actionId,
      frontier_item_id: frontierItemId,
      agent_id: agentId,
      target_ip: '10.10.10.10',
      technique: 'service_enumeration',
      parse_with: 'nmap',
      parse_stream: 'stdout',
      validate: false,
    };
    emit({ type: 'tool_use', name: 'mcp__overwatch__run_tool', input: runInput });
    const scan = await client.callTool({ name: 'run_tool', arguments: runInput });
    const scanPayload = JSON.parse(scan.content[0].text);
    if (scan.isError || scanPayload.executed !== true || scanPayload.parse_summary?.parse_outcome !== 'ok') {
      throw new Error(`hermetic recon execution or parsing failed: ${scan.content[0].text}`);
    }

    const transcriptInput = { task_id: taskId, summary: 'Hermetic recon landed SSH/22 and HTTP/80 from the isolated nmap fixture.' };
    emit({ type: 'tool_use', name: 'mcp__overwatch__submit_agent_transcript', input: transcriptInput });
    await client.callTool({ name: 'submit_agent_transcript', arguments: transcriptInput });
    const completionInput = { task_id: taskId, status: 'completed', summary: 'hermetic recon complete' };
    emit({ type: 'tool_use', name: 'mcp__overwatch__update_agent', input: completionInput });
    await client.callTool({ name: 'update_agent', arguments: completionInput });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'auto' && !childArchetype) {
    // PRIMARY orchestrator (orchestrator task → no archetype): scripted loop for the
    // deterministic plumbing smoke — orient → externalize a decision → dispatch a
    // matched child → re-orient (synthesize) → close. The dispatched child runs as a
    // fake 'auto' child (it HAS an archetype) and lands type-appropriate findings, so
    // the whole orchestration pipeline is exercised without a real model.
    await client.callTool({ name: 'get_state', arguments: {} });
    await client.callTool({ name: 'log_thought', arguments: { kind: 'decision', thought: 'orchestrate: dispatch recon for the host frontier' } });
    await client.callTool({ name: 'register_agent', arguments: { agent_id: `child-${taskId}`, archetype: 'recon_scanner' } });
    await client.callTool({ name: 'get_state', arguments: {} }); // synthesize: re-orient after dispatching
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: 'fake orchestration: dispatched 1 recon child' } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'fake orchestration done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'auto') {
    // Orchestration-eval child: land findings matched to THIS child's archetype
    // (read from get_agent_context above) so a real PRIMARY's dispatch→synthesize
    // loop sees plausible, type-appropriate progress — not a canned blob. Unique
    // ids per task avoid collisions when the primary dispatches many children.
    const u = (s) => `${s}-${taskId}`;
    let nodes;
    let edges = [];
    if (childArchetype === 'web_tester') {
      nodes = [
        { id: u('web'), type: 'webapp', label: `http://10.10.20.9/${taskId}`, properties: { url: `http://10.10.20.9/${taskId}` } },
        { id: u('vuln'), type: 'vulnerability', label: 'reflected XSS', properties: { vuln_type: 'xss', severity: 'medium' } },
      ];
      edges = [{ source: u('web'), target: u('vuln'), type: 'VULNERABLE_TO', confidence: 0.8 }];
    } else if (childArchetype === 'cloud_cartographer' || childArchetype === 'credential_operator' || childArchetype === 'post_exploit') {
      nodes = [
        { id: u('cid'), type: 'cloud_identity', label: `arn:aws:iam::1111:user/${taskId}`, principal_type: 'user', provider: 'aws' },
        { id: u('role'), type: 'cloud_identity', label: `arn:aws:iam::1111:role/Admin-${taskId}`, principal_type: 'role', provider: 'aws' },
      ];
      edges = [{ source: u('cid'), target: u('role'), type: 'ASSUMES_ROLE', confidence: 0.9 }];
    } else if (childArchetype === 'osint_recon') {
      nodes = [{ id: u('dom'), type: 'domain', label: `sub-${taskId}.example.com`, properties: {} }];
    } else {
      // recon_scanner / default / others: a live host + service.
      const oct = (taskId.length % 250) + 1;
      nodes = [
        { id: u('host'), type: 'host', label: `10.10.10.${oct}`, properties: { ip: `10.10.10.${oct}`, alive: true } },
        { id: u('svc'), type: 'service', label: 'ssh/22', properties: { port: 22, protocol: 'tcp', service_name: 'ssh' } },
      ];
      edges = [{ source: u('host'), target: u('svc'), type: 'RUNS', confidence: 1 }];
    }
    await client.callTool({ name: 'report_finding', arguments: { agent_id: agentId, nodes, edges } });
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: `fake ${childArchetype || 'auto'} child: ${nodes.length} nodes` } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: `fake ${childArchetype || 'auto'} done` } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'hang') {
    // Connect and idle forever — the test cancels us.
    emit({ type: 'assistant', text: 'hanging' });
    setInterval(() => {}, 1000);
    return;
  }

  if (mode === 'research') {
    // CVE research role: find the assigned service in the scoped subgraph and
    // record a synthetic candidate via research_cve (no real web access).
    let serviceId;
    try {
      const ctx = await client.callTool({ name: 'get_agent_context', arguments: { task_id: taskId } });
      const parsed = JSON.parse(ctx.content[0].text);
      const svc = (parsed.subgraph?.nodes || []).find((n) => (n.properties?.type || n.type) === 'service');
      serviceId = svc?.id;
    } catch { /* fall through */ }
    if (serviceId) {
      await client.callTool({
        name: 'research_cve',
        arguments: {
          service_id: serviceId,
          agent_id: agentId,
          summary: 'fake research: one applicable candidate',
          candidates: [{ cve: 'CVE-2021-41773', title: 'Apache path traversal', cvss: 7.5, vuln_type: 'lfi', exploit_available: true, poc_url: 'https://example/poc', applicable: true, confidence: 0.8 }],
        },
      });
    }
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: 'fake research complete' } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'fake research done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'planner') {
    // Planner role: translate the operator command into a plan. The objective
    // (embedded in the -p prompt) lists the steerable task_ids; pick a running
    // task that isn't us and propose a `pause` directive on it via propose_plan.
    const prompt = argValue('-p') || '';
    const targetIds = [...prompt.matchAll(/task_id="([^"]+)"/g)].map(m => m[1]).filter(id => id !== taskId);
    // If a steerable peer task is named in the objective, propose a directive on it;
    // otherwise fall back to a scope op (valid without a peer task) so the planner
    // always submits *some* valid plan — exercising the propose_plan path end-to-end.
    const ops = targetIds.length
      ? [{ op: 'directive', task_id: targetIds[0], agent_label: 'target', kind: 'pause' }]
      : [{ op: 'scope', add_cidrs: ['10.99.99.0/24'] }];
    const gate = process.env.OVERWATCH_FAKE_PLANNER_GATE;
    if (gate) {
      writeFileSync(`${gate}.ready`, taskId ?? 'unknown');
      while (!existsSync(`${gate}.release`)) {
        await new Promise(resolve => setTimeout(resolve, 25));
      }
    }
    await client.callTool({
      name: 'propose_plan',
      arguments: {
        agent_id: agentId,
        task_id: taskId,
        summary: targetIds.length ? `pause ${targetIds[0]}` : 'add 10.99.99.0/24 to scope',
        rationale: 'fake planner proposed a plan',
        ops,
      },
    });
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: 'fake planner proposed a plan' } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'fake planner done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'ask') {
    // Escalation: ask the operator a question, then wait for the answer by
    // heartbeating until pending_answer arrives (3D), then close out.
    const askRes = await client.callTool({
      name: 'ask_operator',
      arguments: { task_id: taskId, agent_id: agentId, question: 'go loud or stay quiet?', options: ['loud', 'quiet'] },
    });
    let myQueryId;
    try { myQueryId = JSON.parse(askRes.content[0].text).query_id; } catch { /* ignore */ }
    let answer;
    for (let i = 0; i < 50 && !answer; i++) {
      const hb = await client.callTool({ name: 'agent_heartbeat', arguments: { task_id: taskId } });
      try {
        const parsed = JSON.parse(hb.content[0].text);
        // Act only on the answer to OUR question (matches query_id).
        if (parsed.pending_answer && parsed.pending_answer.query_id === myQueryId) answer = parsed.pending_answer.answer;
      } catch { /* ignore */ }
      if (!answer) await new Promise(r => setTimeout(r, 150));
    }
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: `proceeded with: ${answer ?? 'no answer'}` } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: `operator answer: ${answer ?? 'none'}` } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'opsec') {
    // opsec_sentinel: read the OPSEC posture. No try/catch — if get_opsec_status
    // errors the process exits non-zero and the task is interrupted, so an eval
    // asserting 'completed' proves the tool works end-to-end.
    const res = await client.callTool({ name: 'get_opsec_status', arguments: {} });
    const parsed = JSON.parse(res.content[0].text);
    if (typeof parsed.global_noise_spent !== 'number') throw new Error('get_opsec_status missing global_noise_spent');
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: `opsec posture reviewed (noise ${parsed.global_noise_spent})` } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'opsec review done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'recon') {
    // recon_scanner capability: discovery output → host + service nodes + RUNS edge.
    await client.callTool({
      name: 'report_finding',
      arguments: {
        agent_id: agentId,
        nodes: [
          { id: 'host-recon-eval', type: 'host', label: '10.10.10.42', properties: { ip: '10.10.10.42', hostname: 'recon-target', alive: true } },
          { id: 'svc-recon-ssh', type: 'service', label: 'ssh/22', properties: { port: 22, protocol: 'tcp', service_name: 'ssh' } },
        ],
        edges: [{ source: 'host-recon-eval', target: 'svc-recon-ssh', type: 'RUNS', confidence: 1 }],
      },
    });
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: 'fake recon: 1 host, 1 service' } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'fake recon done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'audit') {
    // evidence_auditor: read the per-finding proof-readiness rollup. No try/catch —
    // if get_finding_readiness errors the process exits non-zero and the task is
    // interrupted, so an eval asserting 'completed' proves the tool works end-to-end.
    const res = await client.callTool({ name: 'get_finding_readiness', arguments: {} });
    const parsed = JSON.parse(res.content[0].text);
    if (!parsed.summary || typeof parsed.summary.total !== 'number') throw new Error('get_finding_readiness missing summary.total');
    if (!Array.isArray(parsed.findings)) throw new Error('get_finding_readiness missing findings array');
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: `audited ${parsed.summary.total} findings (${parsed.summary.client_ready} client-ready)` } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'evidence audit done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'shepherd') {
    // session_shepherd: read-only session oversight. The fixture seeds one session,
    // so list_sessions must return it; then read its buffer. No try/catch — a tool
    // error exits non-zero and the task is interrupted, so 'completed' proves the
    // read-only session tools work end-to-end through the shepherd allowlist.
    const listed = await client.callTool({ name: 'list_sessions', arguments: {} });
    const parsed = JSON.parse(listed.content[0].text);
    if (typeof parsed.total !== 'number' || !Array.isArray(parsed.sessions)) throw new Error('list_sessions missing total/sessions');
    const first = parsed.sessions[0];
    if (first?.id) await client.callTool({ name: 'read_session', arguments: { session_id: first.id } });
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: `reviewed ${parsed.total} session(s), ${parsed.active} active` } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'session oversight done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'cloud') {
    // cloud_cartographer capability: map a cloud identity assuming a privileged
    // role (the cartographer's signature — federation / role assumption).
    await client.callTool({
      name: 'report_finding',
      arguments: {
        agent_id: agentId,
        nodes: [
          { id: 'cloud-user-eval', type: 'cloud_identity', label: 'arn:aws:iam::111122223333:user/dev', principal_type: 'user', provider: 'aws' },
          { id: 'cloud-role-eval', type: 'cloud_identity', label: 'arn:aws:iam::111122223333:role/AdminRole', principal_type: 'role', provider: 'aws' },
        ],
        edges: [{ source: 'cloud-user-eval', target: 'cloud-role-eval', type: 'ASSUMES_ROLE', confidence: 0.9 }],
      },
    });
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: 'fake cloud: 1 identity assumes 1 role' } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'fake cloud done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'web') {
    // web_tester capability: a discovered web app + a candidate vulnerability.
    await client.callTool({
      name: 'report_finding',
      arguments: {
        agent_id: agentId,
        nodes: [
          { id: 'web-eval-app', type: 'webapp', label: 'http://10.10.10.50/', properties: { url: 'http://10.10.10.50/', title: 'eval app' } },
          { id: 'vuln-eval-xss', type: 'vulnerability', label: 'reflected XSS', properties: { vuln_type: 'xss', severity: 'medium' } },
        ],
        edges: [{ source: 'web-eval-app', target: 'vuln-eval-xss', type: 'VULNERABLE_TO', confidence: 0.8 }],
      },
    });
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: 'fake web: 1 app, 1 vuln' } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'fake web done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'cred') {
    // credential_operator: find the assigned AWS-flavored credential in scope and
    // expand it into a recon plan (plan generation only — no live AWS). No try/catch
    // on expand_aws_credential: if it errors the task is interrupted, so 'completed'
    // proves the credential playbook works through the credential_operator allowlist.
    let credId;
    try {
      const ctx = await client.callTool({ name: 'get_agent_context', arguments: { task_id: taskId } });
      const parsed = JSON.parse(ctx.content[0].text);
      const cred = (parsed.subgraph?.nodes || []).find((n) => (n.properties?.type || n.type) === 'credential');
      credId = cred?.id;
    } catch { /* fall through */ }
    if (!credId) throw new Error('cred mode: no credential in scoped subgraph');
    const res = await client.callTool({ name: 'expand_aws_credential', arguments: { credential_id: credId } });
    if (res.isError) throw new Error(`expand_aws_credential failed: ${res.content?.[0]?.text}`);
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: 'expanded 1 AWS credential into a recon plan' } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'credential expansion done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'postex') {
    // post_exploit capability: from a foothold, record a lateral admin-access edge
    // (the post-exploitation signature) via report_finding.
    await client.callTool({
      name: 'report_finding',
      arguments: {
        agent_id: agentId,
        nodes: [
          { id: 'user-admin-eval', type: 'user', label: 'CORP\\\\admin', properties: { username: 'admin', domain: 'corp.local' } },
          { id: 'host-pivot-eval', type: 'host', label: '10.10.10.61', properties: { ip: '10.10.10.61', hostname: 'pivot', alive: true } },
        ],
        // ADMIN_TO is canonically principal→host (graph-schema EDGE_CONSTRAINTS).
        edges: [{ source: 'user-admin-eval', target: 'host-pivot-eval', type: 'ADMIN_TO', confidence: 0.95 }],
      },
    });
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: 'fake post-exploit: 1 lateral admin edge' } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'fake post-exploit done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  if (mode === 'scribe') {
    // report_scribe: draft a report from confirmed graph state via generate_report
    // (read-only synthesis). No try/catch — an error interrupts the task, so
    // 'completed' proves generate_report works through the report_scribe allowlist.
    const res = await client.callTool({ name: 'generate_report', arguments: { format: 'markdown' } });
    const text = res.content?.[0]?.text ?? '';
    if (text.length < 80) throw new Error(`generate_report returned no content (${text.length} chars)`);
    await client.callTool({ name: 'submit_agent_transcript', arguments: { task_id: taskId, summary: `drafted a ${text.length}-char report` } });
    await client.callTool({ name: 'update_agent', arguments: { task_id: taskId, status: 'completed', summary: 'report draft done' } });
    emit({ type: 'result', subtype: 'success', is_error: false });
    await client.close();
    process.exit(0);
  }

  // complete: write a finding, then close the task out.
  await client.callTool({
    name: 'report_finding',
    arguments: {
      agent_id: agentId,
      nodes: [{ id: 'host-fake-77', type: 'host', label: '10.10.10.77', properties: { ip: '10.10.10.77', hostname: 'fake-target' } }],
      edges: [],
    },
  });
  await client.callTool({
    name: 'submit_agent_transcript',
    arguments: { task_id: taskId, summary: 'fake-claude completed its bounded task' },
  });
  await client.callTool({
    name: 'update_agent',
    arguments: { task_id: taskId, status: 'completed', summary: 'fake-claude done' },
  });

  emit({ type: 'result', subtype: 'success', is_error: false });
  await client.close();
  process.exit(0);
}

main().catch((err) => {
  emit({ type: 'result', subtype: 'error', is_error: true, error: String(err) });
  process.exit(1);
});
