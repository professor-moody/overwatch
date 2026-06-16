#!/usr/bin/env node
// ============================================================
// Fake `claude` CLI for headless-runner integration tests.
//
// Stands in for `claude -p ...`: reads the --mcp-config the runner wrote,
// connects to the Overwatch HTTP MCP endpoint as a real MCP client, exercises
// the sub-agent loop (get_agent_context → report_finding → update_agent), and
// emits a couple of stream-json lines. Behavior is selected by env:
//   OVERWATCH_FAKE_MODE = 'complete' (default) | 'hang'
//   OVERWATCH_TASK_ID   = the agent task id (set by the runner)
// ============================================================
import { readFileSync } from 'node:fs';
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

  // Discover scope + agent identity.
  let agentId = 'fake-agent';
  try {
    const ctx = await client.callTool({ name: 'get_agent_context', arguments: { task_id: taskId } });
    const parsed = JSON.parse(ctx.content[0].text);
    if (parsed.agent_id) agentId = parsed.agent_id;
  } catch { /* context optional for the fake */ }

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
