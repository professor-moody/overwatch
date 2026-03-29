#!/usr/bin/env node
// Generates light + dark architecture diagram SVGs from template bodies.
// Run: node scripts/generate-diagram-svgs.js
// Output: docs/assets/{name}-{dark,light}.svg

const fs = require('fs');
const path = require('path');

const ASSETS = path.join(__dirname, '..', 'docs', 'assets');

const MARKER = `<defs><marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></marker></defs>`;

// ── Dark theme ──────────────────────────────────────────────
const DARK_STYLE = `<style>
  text{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif}
  .th{font-size:13px;font-weight:500;fill:#e0e0e0}
  .ts{font-size:11px;fill:#9ca3af}
  .arr{stroke:#6b7280;stroke-width:1}
  .n-purple rect{fill:#26215C;stroke:#534AB7;stroke-width:.5}
  .n-purple .th{fill:#CCFFCC}.n-purple .ts{fill:#AFA9EC}
  .n-blue rect{fill:#0C3A6E;stroke:#378ADD;stroke-width:.5}
  .n-blue .th{fill:#B5D4F4}.n-blue .ts{fill:#85B7EB}
  .n-teal rect{fill:#053B30;stroke:#1D9E75;stroke-width:.5}
  .n-teal .th{fill:#9FE1CB}.n-teal .ts{fill:#5DCAA5}
  .n-amber rect{fill:#3A2800;stroke:#BA7517;stroke-width:.5}
  .n-amber .th{fill:#FAC775}.n-amber .ts{fill:#EF9F27}
  .n-coral rect{fill:#3E1508;stroke:#D85A30;stroke-width:.5}
  .n-coral .th{fill:#F5C4B3}.n-coral .ts{fill:#F0997B}
  .n-pink rect{fill:#3E1028;stroke:#D4537E;stroke-width:.5}
  .n-pink .th{fill:#F4C0D1}.n-pink .ts{fill:#ED93B1}
  .n-gray rect{fill:#1e1e1c;stroke:#5F5E5A;stroke-width:.5}
  .n-gray .th{fill:#D3D1C7}.n-gray .ts{fill:#B4B2A9}
  .n-red rect{fill:#3A0F0F;stroke:#A32D2D;stroke-width:.5}
  .n-red .th{fill:#F7C1C1}.n-red .ts{fill:#F09595}
</style>`;
const DARK_BG = 'transparent';

// ── Light theme ─────────────────────────────────────────────
const LIGHT_STYLE = `<style>
  text{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif}
  .th{font-size:13px;font-weight:500;fill:#1e293b}
  .ts{font-size:11px;fill:#475569}
  .arr{stroke:#94a3b8;stroke-width:1}
  .n-purple rect{fill:#ede9fe;stroke:#8b5cf6;stroke-width:.5}
  .n-purple .th{fill:#5b21b6}.n-purple .ts{fill:#7c3aed}
  .n-blue rect{fill:#dbeafe;stroke:#3b82f6;stroke-width:.5}
  .n-blue .th{fill:#1e40af}.n-blue .ts{fill:#2563eb}
  .n-teal rect{fill:#d1fae5;stroke:#10b981;stroke-width:.5}
  .n-teal .th{fill:#065f46}.n-teal .ts{fill:#059669}
  .n-amber rect{fill:#fef3c7;stroke:#f59e0b;stroke-width:.5}
  .n-amber .th{fill:#92400e}.n-amber .ts{fill:#b45309}
  .n-coral rect{fill:#fff7ed;stroke:#f97316;stroke-width:.5}
  .n-coral .th{fill:#9a3412}.n-coral .ts{fill:#ea580c}
  .n-pink rect{fill:#fce7f3;stroke:#ec4899;stroke-width:.5}
  .n-pink .th{fill:#9d174d}.n-pink .ts{fill:#db2777}
  .n-gray rect{fill:#f1f5f9;stroke:#94a3b8;stroke-width:.5}
  .n-gray .th{fill:#334155}.n-gray .ts{fill:#475569}
  .n-red rect{fill:#fee2e2;stroke:#ef4444;stroke-width:.5}
  .n-red .th{fill:#991b1b}.n-red .ts{fill:#dc2626}
</style>`;
const LIGHT_BG = '#ffffff';

// ── Diagram bodies (element content only, no <svg> wrapper) ─

const diagrams = [
  {
    name: 'system-architecture',
    viewBox: '0 0 680 480',
    body: `
  <g class="n-purple"><rect x="200" y="20" width="280" height="50" rx="8"/><text class="th" x="340" y="40" text-anchor="middle" dominant-baseline="central">LLM operator (Claude / Opus)</text><text class="ts" x="340" y="56" text-anchor="middle" dominant-baseline="central">Primary session + sub-agents</text></g>
  <line x1="290" y1="70" x2="290" y2="110" class="arr" marker-end="url(#arr)"/><line x1="390" y1="110" x2="390" y2="70" class="arr" marker-end="url(#arr)"/>
  <text class="ts" x="252" y="94" text-anchor="end">stdio / HTTP+SSE</text>
  <g class="n-teal"><rect x="60" y="110" width="560" height="290" rx="14"/><text class="th" x="340" y="134" text-anchor="middle" dominant-baseline="central">MCP orchestrator server</text></g>
  <g class="n-blue"><rect x="90" y="150" width="500" height="36" rx="7"/><text class="th" x="340" y="168" text-anchor="middle" dominant-baseline="central">39 MCP tools (Zod-validated)</text></g>
  <g class="n-amber"><rect x="90" y="200" width="150" height="50" rx="7"/><text class="th" x="165" y="218" text-anchor="middle" dominant-baseline="central">Graph engine</text><text class="ts" x="165" y="234" text-anchor="middle" dominant-baseline="central">graphology</text></g>
  <g class="n-coral"><rect x="262" y="200" width="150" height="50" rx="7"/><text class="th" x="337" y="218" text-anchor="middle" dominant-baseline="central">Inference engine</text><text class="ts" x="337" y="234" text-anchor="middle" dominant-baseline="central">22 rules</text></g>
  <g class="n-pink"><rect x="434" y="200" width="150" height="50" rx="7"/><text class="th" x="509" y="218" text-anchor="middle" dominant-baseline="central">Frontier computer</text><text class="ts" x="509" y="234" text-anchor="middle" dominant-baseline="central">Next actions</text></g>
  <line x1="240" y1="225" x2="260" y2="225" class="arr" marker-end="url(#arr)"/><line x1="412" y1="225" x2="432" y2="225" class="arr" marker-end="url(#arr)"/>
  <g class="n-gray"><rect x="90" y="266" width="500" height="36" rx="7"/><text class="th" x="340" y="284" text-anchor="middle" dominant-baseline="central">EngineContext (shared mutable state)</text></g>
  <g class="n-teal"><rect x="90" y="318" width="120" height="36" rx="6"/><text class="ts" x="150" y="336" text-anchor="middle" dominant-baseline="central">Path analyzer</text></g>
  <g class="n-teal"><rect x="224" y="318" width="120" height="36" rx="6"/><text class="ts" x="284" y="336" text-anchor="middle" dominant-baseline="central">Identity resolution</text></g>
  <g class="n-teal"><rect x="358" y="318" width="120" height="36" rx="6"/><text class="ts" x="418" y="336" text-anchor="middle" dominant-baseline="central">State persistence</text></g>
  <g class="n-teal"><rect x="492" y="318" width="100" height="36" rx="6"/><text class="ts" x="542" y="336" text-anchor="middle" dominant-baseline="central">17 parsers</text></g>
  <g class="n-gray"><rect x="350" y="372" width="90" height="26" rx="6"/><text class="ts" x="395" y="385" text-anchor="middle" dominant-baseline="central">state.json</text></g>
  <line x1="418" y1="354" x2="395" y2="372" class="arr" marker-end="url(#arr)"/>
  <g class="n-blue"><rect x="200" y="430" width="280" height="40" rx="8"/><text class="th" x="340" y="450" text-anchor="middle" dominant-baseline="central">Dashboard (sigma.js WebGL :8384)</text></g>
  <line x1="340" y1="400" x2="340" y2="430" class="arr" marker-end="url(#arr)"/>
  <text class="ts" x="355" y="418" text-anchor="start">WebSocket deltas</text>`
  },

  {
    name: 'data-flow-lifecycle',
    viewBox: '0 0 680 640',
    body: `
  <g class="n-purple"><rect x="180" y="10" width="320" height="40" rx="7"/><text class="th" x="340" y="30" text-anchor="middle" dominant-baseline="central">1. validate_action() → action_id</text></g>
  <line x1="340" y1="50" x2="340" y2="66" class="arr" marker-end="url(#arr)"/>
  <g class="n-blue"><rect x="180" y="66" width="320" height="48" rx="7"/><text class="th" x="340" y="84" text-anchor="middle" dominant-baseline="central">2. Deterministic validation</text><text class="ts" x="340" y="100" text-anchor="middle" dominant-baseline="central">Scope, dedup, OPSEC check</text></g>
  <line x1="340" y1="114" x2="340" y2="130" class="arr" marker-end="url(#arr)"/>
  <g class="n-gray"><rect x="180" y="130" width="320" height="40" rx="7"/><text class="th" x="340" y="150" text-anchor="middle" dominant-baseline="central">3. log_action_event(started)</text></g>
  <line x1="340" y1="170" x2="340" y2="186" class="arr" marker-end="url(#arr)"/>
  <g class="n-amber"><rect x="180" y="186" width="320" height="48" rx="7"/><text class="th" x="340" y="204" text-anchor="middle" dominant-baseline="central">4. Execute (bash / nmap / nxc)</text><text class="ts" x="340" y="220" text-anchor="middle" dominant-baseline="central">Claude Code native bash</text></g>
  <line x1="340" y1="234" x2="340" y2="250" class="arr" marker-end="url(#arr)"/>
  <g class="n-coral"><rect x="80" y="250" width="240" height="48" rx="7"/><text class="th" x="200" y="268" text-anchor="middle" dominant-baseline="central">5a. parse_output()</text><text class="ts" x="200" y="284" text-anchor="middle" dominant-baseline="central">17 parsers / 31 aliases</text></g>
  <g class="n-coral"><rect x="360" y="250" width="240" height="48" rx="7"/><text class="th" x="480" y="268" text-anchor="middle" dominant-baseline="central">5b. report_finding()</text><text class="ts" x="480" y="284" text-anchor="middle" dominant-baseline="central">Manual nodes/edges</text></g>
  <text class="ts" x="340" y="278" text-anchor="middle">or</text>
  <line x1="200" y1="298" x2="200" y2="322" class="arr" marker-end="url(#arr)"/><line x1="480" y1="298" x2="480" y2="322" class="arr" marker-end="url(#arr)"/>
  <g class="n-teal"><rect x="100" y="322" width="480" height="48" rx="7"/><text class="th" x="340" y="340" text-anchor="middle" dominant-baseline="central">6. Graph engine ingests</text><text class="ts" x="340" y="356" text-anchor="middle" dominant-baseline="central">Identity resolution, dedup, cold store triage</text></g>
  <line x1="340" y1="370" x2="340" y2="386" class="arr" marker-end="url(#arr)"/>
  <g class="n-pink"><rect x="140" y="386" width="400" height="48" rx="7"/><text class="th" x="340" y="404" text-anchor="middle" dominant-baseline="central">7. Inference rules fire</text><text class="ts" x="340" y="420" text-anchor="middle" dominant-baseline="central">Hypothesis edges (confidence 0.3-0.7)</text></g>
  <line x1="340" y1="434" x2="340" y2="450" class="arr" marker-end="url(#arr)"/>
  <g class="n-blue"><rect x="140" y="450" width="400" height="48" rx="7"/><text class="th" x="340" y="468" text-anchor="middle" dominant-baseline="central">8. Frontier recomputed + state persisted</text><text class="ts" x="340" y="484" text-anchor="middle" dominant-baseline="central">Atomic write-rename, snapshot rotation</text></g>
  <line x1="340" y1="498" x2="340" y2="514" class="arr" marker-end="url(#arr)"/>
  <g class="n-gray"><rect x="140" y="514" width="400" height="48" rx="7"/><text class="th" x="340" y="532" text-anchor="middle" dominant-baseline="central">9. Dashboard broadcast + next_task()</text><text class="ts" x="340" y="548" text-anchor="middle" dominant-baseline="central">WebSocket delta → UI; frontier → LLM</text></g>
  <path d="M540 540 L610 540 L610 30 L502 30" fill="none" class="arr" marker-end="url(#arr)" stroke-dasharray="4 3"/>
  <text class="ts" x="622" y="290" text-anchor="start" transform="rotate(90 622 290)">Loop</text>`
  },

  {
    name: 'hybrid-scoring',
    viewBox: '0 0 680 400',
    body: `
  <g class="n-blue"><rect x="40" y="40" width="280" height="280" rx="14"/><text class="th" x="180" y="64" text-anchor="middle" dominant-baseline="central">Deterministic layer</text><text class="ts" x="180" y="80" text-anchor="middle" dominant-baseline="central">Guardrail, not brain</text></g>
  <g class="n-blue"><rect x="70" y="98" width="220" height="30" rx="5"/><text class="ts" x="180" y="113" text-anchor="middle" dominant-baseline="central">Scope enforcement (CIDR/domain)</text></g>
  <g class="n-blue"><rect x="70" y="136" width="220" height="30" rx="5"/><text class="ts" x="180" y="151" text-anchor="middle" dominant-baseline="central">Deduplication (tested edges)</text></g>
  <g class="n-blue"><rect x="70" y="174" width="220" height="30" rx="5"/><text class="ts" x="180" y="189" text-anchor="middle" dominant-baseline="central">OPSEC vetoes (noise ceiling)</text></g>
  <g class="n-blue"><rect x="70" y="212" width="220" height="30" rx="5"/><text class="ts" x="180" y="227" text-anchor="middle" dominant-baseline="central">Inference rule execution</text></g>
  <g class="n-blue"><rect x="70" y="250" width="220" height="30" rx="5"/><text class="ts" x="180" y="265" text-anchor="middle" dominant-baseline="central">Frontier generation</text></g>
  <g class="n-blue"><rect x="70" y="288" width="220" height="30" rx="5"/><text class="ts" x="180" y="303" text-anchor="middle" dominant-baseline="central">Dead host pruning</text></g>
  <g class="n-purple"><rect x="360" y="40" width="280" height="280" rx="14"/><text class="th" x="500" y="64" text-anchor="middle" dominant-baseline="central">LLM layer</text><text class="ts" x="500" y="80" text-anchor="middle" dominant-baseline="central">Offensive reasoning</text></g>
  <g class="n-purple"><rect x="390" y="98" width="220" height="30" rx="5"/><text class="ts" x="500" y="113" text-anchor="middle" dominant-baseline="central">Attack chain spotting</text></g>
  <g class="n-purple"><rect x="390" y="136" width="220" height="30" rx="5"/><text class="ts" x="500" y="151" text-anchor="middle" dominant-baseline="central">Sequencing decisions</text></g>
  <g class="n-purple"><rect x="390" y="174" width="220" height="30" rx="5"/><text class="ts" x="500" y="189" text-anchor="middle" dominant-baseline="central">Risk/reward assessment</text></g>
  <g class="n-purple"><rect x="390" y="212" width="220" height="30" rx="5"/><text class="ts" x="500" y="227" text-anchor="middle" dominant-baseline="central">Creative path discovery</text></g>
  <g class="n-purple"><rect x="390" y="250" width="220" height="30" rx="5"/><text class="ts" x="500" y="265" text-anchor="middle" dominant-baseline="central">Tool command construction</text></g>
  <g class="n-purple"><rect x="390" y="288" width="220" height="30" rx="5"/><text class="ts" x="500" y="303" text-anchor="middle" dominant-baseline="central">Agent dispatch decisions</text></g>
  <g class="n-amber"><rect x="160" y="354" width="360" height="34" rx="7"/><text class="th" x="340" y="371" text-anchor="middle" dominant-baseline="central">Directed property graph (shared interface)</text></g>
  <line x1="180" y1="320" x2="260" y2="354" class="arr" marker-end="url(#arr)"/><line x1="500" y1="320" x2="420" y2="354" class="arr" marker-end="url(#arr)"/>`
  },

  {
    name: 'inference-lifecycle',
    viewBox: '0 0 680 500',
    body: `
  <g class="n-coral"><rect x="180" y="10" width="320" height="48" rx="7"/><text class="th" x="340" y="28" text-anchor="middle" dominant-baseline="central">Finding ingested</text><text class="ts" x="340" y="44" text-anchor="middle" dominant-baseline="central">New node/edge enters graph</text></g>
  <line x1="340" y1="58" x2="340" y2="76" class="arr" marker-end="url(#arr)"/>
  <g class="n-amber"><rect x="120" y="76" width="440" height="48" rx="7"/><text class="th" x="340" y="94" text-anchor="middle" dominant-baseline="central">Rule matching (22 built-in rules)</text><text class="ts" x="340" y="110" text-anchor="middle" dominant-baseline="central">Node type + property + edge-triggered</text></g>
  <line x1="140" y1="124" x2="140" y2="148" class="arr" marker-end="url(#arr)"/>
  <line x1="290" y1="124" x2="290" y2="148" class="arr" marker-end="url(#arr)"/>
  <line x1="430" y1="124" x2="430" y2="148" class="arr" marker-end="url(#arr)"/>
  <line x1="560" y1="124" x2="560" y2="148" class="arr" marker-end="url(#arr)"/>
  <g class="n-teal"><rect x="80" y="148" width="110" height="40" rx="6"/><text class="ts" x="135" y="163" text-anchor="middle" dominant-baseline="central">AD + service</text><text class="ts" x="135" y="178" text-anchor="middle" dominant-baseline="central">13 rules</text></g>
  <g class="n-teal"><rect x="230" y="148" width="110" height="40" rx="6"/><text class="ts" x="285" y="163" text-anchor="middle" dominant-baseline="central">Linux privesc</text><text class="ts" x="285" y="178" text-anchor="middle" dominant-baseline="central">4 rules</text></g>
  <g class="n-teal"><rect x="380" y="148" width="110" height="40" rx="6"/><text class="ts" x="435" y="163" text-anchor="middle" dominant-baseline="central">Web + MSSQL</text><text class="ts" x="435" y="178" text-anchor="middle" dominant-baseline="central">2 rules</text></g>
  <g class="n-teal"><rect x="520" y="148" width="90" height="40" rx="6"/><text class="ts" x="565" y="163" text-anchor="middle" dominant-baseline="central">Cloud</text><text class="ts" x="565" y="178" text-anchor="middle" dominant-baseline="central">3 rules</text></g>
  <line x1="135" y1="188" x2="135" y2="206" stroke="#6b7280" stroke-width=".5"/><line x1="285" y1="188" x2="285" y2="206" stroke="#6b7280" stroke-width=".5"/>
  <line x1="435" y1="188" x2="435" y2="206" stroke="#6b7280" stroke-width=".5"/><line x1="565" y1="188" x2="565" y2="206" stroke="#6b7280" stroke-width=".5"/>
  <line x1="135" y1="206" x2="565" y2="206" stroke="#6b7280" stroke-width=".5"/>
  <line x1="340" y1="206" x2="340" y2="226" class="arr" marker-end="url(#arr)"/>
  <g class="n-purple"><rect x="140" y="226" width="400" height="48" rx="7"/><text class="th" x="340" y="244" text-anchor="middle" dominant-baseline="central">Selector resolution (15 selectors)</text><text class="ts" x="340" y="260" text-anchor="middle" dominant-baseline="central">all_compromised, edge_peers, domain_creds, ...</text></g>
  <line x1="340" y1="274" x2="340" y2="294" class="arr" marker-end="url(#arr)"/>
  <g class="n-pink"><rect x="140" y="294" width="400" height="48" rx="7"/><text class="th" x="340" y="312" text-anchor="middle" dominant-baseline="central">Hypothesis edges created</text><text class="ts" x="340" y="328" text-anchor="middle" dominant-baseline="central">Confidence 0.3-0.7, inferred_by_rule tagged</text></g>
  <line x1="340" y1="342" x2="340" y2="362" class="arr" marker-end="url(#arr)"/>
  <g class="n-blue"><rect x="140" y="362" width="400" height="48" rx="7"/><text class="th" x="340" y="380" text-anchor="middle" dominant-baseline="central">Frontier items (type: inferred_edge)</text><text class="ts" x="340" y="396" text-anchor="middle" dominant-baseline="central">Surfaced via next_task()</text></g>
  <line x1="340" y1="410" x2="340" y2="430" class="arr" marker-end="url(#arr)"/>
  <g class="n-gray"><rect x="140" y="430" width="400" height="48" rx="7"/><text class="th" x="340" y="448" text-anchor="middle" dominant-baseline="central">LLM tests → confidence raised to 1.0</text><text class="ts" x="340" y="464" text-anchor="middle" dominant-baseline="central">Or discarded on failure</text></g>`
  },

  {
    name: 'compaction-persistence',
    viewBox: '0 0 680 450',
    body: `
  <g class="n-coral"><rect x="40" y="20" width="180" height="40" rx="7"/><text class="ts" x="130" y="40" text-anchor="middle" dominant-baseline="central">Context compaction</text></g>
  <g class="n-coral"><rect x="250" y="20" width="180" height="40" rx="7"/><text class="ts" x="340" y="40" text-anchor="middle" dominant-baseline="central">Server restart</text></g>
  <g class="n-coral"><rect x="460" y="20" width="180" height="40" rx="7"/><text class="ts" x="550" y="40" text-anchor="middle" dominant-baseline="central">Session handoff</text></g>
  <line x1="130" y1="60" x2="130" y2="90" class="arr" marker-end="url(#arr)"/><line x1="340" y1="60" x2="340" y2="90" class="arr" marker-end="url(#arr)"/><line x1="550" y1="60" x2="550" y2="90" class="arr" marker-end="url(#arr)"/>
  <g class="n-amber"><rect x="40" y="90" width="600" height="50" rx="10"/><text class="th" x="340" y="108" text-anchor="middle" dominant-baseline="central">Graph lives outside the context window</text><text class="ts" x="340" y="126" text-anchor="middle" dominant-baseline="central">MCP server = external persistent process, not a prompt</text></g>
  <line x1="340" y1="140" x2="340" y2="164" class="arr" marker-end="url(#arr)"/>
  <g class="n-gray"><rect x="140" y="164" width="400" height="50" rx="8"/><text class="th" x="340" y="182" text-anchor="middle" dominant-baseline="central">Atomic write-rename persistence</text><text class="ts" x="340" y="200" text-anchor="middle" dominant-baseline="central">Serialize → tmp file → rename → snapshot rotation</text></g>
  <line x1="340" y1="214" x2="340" y2="238" class="arr" marker-end="url(#arr)"/>
  <g class="n-blue"><rect x="100" y="238" width="480" height="40" rx="7"/><text class="th" x="340" y="258" text-anchor="middle" dominant-baseline="central">get_state() reconstructs complete briefing</text></g>
  <line x1="340" y1="278" x2="340" y2="302" class="arr" marker-end="url(#arr)"/>
  <g class="n-purple"><rect x="40" y="302" width="600" height="80" rx="12"/><text class="th" x="340" y="322" text-anchor="middle" dominant-baseline="central">Reconstructed engagement state</text></g>
  <g class="n-purple"><rect x="62" y="338" width="100" height="30" rx="5"/><text class="ts" x="112" y="353" text-anchor="middle" dominant-baseline="central">Scope + config</text></g>
  <g class="n-purple"><rect x="174" y="338" width="100" height="30" rx="5"/><text class="ts" x="224" y="353" text-anchor="middle" dominant-baseline="central">All discoveries</text></g>
  <g class="n-purple"><rect x="286" y="338" width="100" height="30" rx="5"/><text class="ts" x="336" y="353" text-anchor="middle" dominant-baseline="central">Frontier items</text></g>
  <g class="n-purple"><rect x="398" y="338" width="100" height="30" rx="5"/><text class="ts" x="448" y="353" text-anchor="middle" dominant-baseline="central">Active agents</text></g>
  <g class="n-purple"><rect x="510" y="338" width="110" height="30" rx="5"/><text class="ts" x="565" y="353" text-anchor="middle" dominant-baseline="central">Recent activity</text></g>
  <text class="ts" x="340" y="416" text-anchor="middle">Also: cold_node_count, cold_nodes_by_subnet, community_ids, objective progress</text>`
  },

  {
    name: 'session-transport',
    viewBox: '0 0 680 420',
    body: `
  <g class="n-purple"><rect x="60" y="10" width="250" height="48" rx="7"/><text class="th" x="185" y="28" text-anchor="middle" dominant-baseline="central">stdio transport</text><text class="ts" x="185" y="44" text-anchor="middle" dominant-baseline="central">Claude Code default</text></g>
  <g class="n-blue"><rect x="370" y="10" width="250" height="48" rx="7"/><text class="th" x="495" y="28" text-anchor="middle" dominant-baseline="central">HTTP/SSE transport</text><text class="ts" x="495" y="44" text-anchor="middle" dominant-baseline="central">Multi-client, remote</text></g>
  <line x1="185" y1="58" x2="185" y2="74" stroke="#6b7280" stroke-width=".5"/><line x1="495" y1="58" x2="495" y2="74" stroke="#6b7280" stroke-width=".5"/>
  <line x1="185" y1="74" x2="495" y2="74" stroke="#6b7280" stroke-width=".5"/><line x1="340" y1="74" x2="340" y2="90" class="arr" marker-end="url(#arr)"/>
  <g class="n-amber"><rect x="140" y="90" width="400" height="40" rx="7"/><text class="th" x="340" y="110" text-anchor="middle" dominant-baseline="central">app.ts (transport-neutral, 39 tools)</text></g>
  <line x1="340" y1="130" x2="340" y2="152" class="arr" marker-end="url(#arr)"/>
  <text class="th" x="340" y="166" text-anchor="middle" dominant-baseline="central">Session manager</text>
  <g class="n-teal"><rect x="44" y="180" width="180" height="48" rx="7"/><text class="th" x="134" y="198" text-anchor="middle" dominant-baseline="central">LocalPty adapter</text><text class="ts" x="134" y="214" text-anchor="middle" dominant-baseline="central">node-pty, full TTY</text></g>
  <g class="n-teal"><rect x="250" y="180" width="180" height="48" rx="7"/><text class="th" x="340" y="198" text-anchor="middle" dominant-baseline="central">SSH adapter</text><text class="ts" x="340" y="214" text-anchor="middle" dominant-baseline="central">Key/password auth</text></g>
  <g class="n-teal"><rect x="456" y="180" width="180" height="48" rx="7"/><text class="th" x="546" y="198" text-anchor="middle" dominant-baseline="central">Socket adapter</text><text class="ts" x="546" y="214" text-anchor="middle" dominant-baseline="central">Reverse shells</text></g>
  <line x1="134" y1="228" x2="134" y2="250" stroke="#6b7280" stroke-width=".5"/><line x1="340" y1="228" x2="340" y2="250" stroke="#6b7280" stroke-width=".5"/><line x1="546" y1="228" x2="546" y2="250" stroke="#6b7280" stroke-width=".5"/>
  <line x1="134" y1="250" x2="546" y2="250" stroke="#6b7280" stroke-width=".5"/><line x1="340" y1="250" x2="340" y2="268" class="arr" marker-end="url(#arr)"/>
  <g class="n-coral"><rect x="140" y="268" width="400" height="48" rx="7"/><text class="th" x="340" y="286" text-anchor="middle" dominant-baseline="central">128KB ring buffer per session</text><text class="ts" x="340" y="302" text-anchor="middle" dominant-baseline="central">Cursor-based, monotonic positions</text></g>
  <line x1="340" y1="316" x2="340" y2="338" class="arr" marker-end="url(#arr)"/>
  <g class="n-gray"><rect x="100" y="338" width="90" height="32" rx="6"/><text class="ts" x="145" y="354" text-anchor="middle" dominant-baseline="central">pending</text></g>
  <line x1="190" y1="354" x2="240" y2="354" class="arr" marker-end="url(#arr)"/>
  <g class="n-teal"><rect x="240" y="338" width="110" height="32" rx="6"/><text class="ts" x="295" y="354" text-anchor="middle" dominant-baseline="central">connected</text></g>
  <line x1="350" y1="354" x2="406" y2="354" class="arr" marker-end="url(#arr)"/>
  <g class="n-gray"><rect x="406" y="338" width="80" height="32" rx="6"/><text class="ts" x="446" y="354" text-anchor="middle" dominant-baseline="central">closed</text></g>
  <line x1="295" y1="370" x2="295" y2="390" class="arr" marker-end="url(#arr)"/>
  <g class="n-red"><rect x="258" y="390" width="74" height="26" rx="5"/><text class="ts" x="295" y="403" text-anchor="middle" dominant-baseline="central">error</text></g>
  <text class="ts" x="530" y="354" text-anchor="start">TTY: none → dumb → partial → full</text>`
  },

  {
    name: 'dashboard-pipeline',
    viewBox: '0 0 680 380',
    body: `
  <g class="n-teal"><rect x="40" y="10" width="600" height="170" rx="12"/><text class="th" x="340" y="30" text-anchor="middle" dominant-baseline="central">MCP server process</text></g>
  <g class="n-amber"><rect x="80" y="44" width="200" height="38" rx="7"/><text class="th" x="180" y="63" text-anchor="middle" dominant-baseline="central">GraphEngine.persist()</text></g>
  <line x1="280" y1="63" x2="314" y2="63" class="arr" marker-end="url(#arr)"/>
  <g class="n-coral"><rect x="314" y="44" width="200" height="38" rx="7"/><text class="th" x="414" y="63" text-anchor="middle" dominant-baseline="central">onUpdate callback</text></g>
  <line x1="414" y1="82" x2="414" y2="102" class="arr" marker-end="url(#arr)"/>
  <g class="n-purple"><rect x="260" y="102" width="240" height="38" rx="7"/><text class="th" x="380" y="121" text-anchor="middle" dominant-baseline="central">Delta accumulator (debounced)</text></g>
  <line x1="280" y1="140" x2="220" y2="152" class="arr" marker-end="url(#arr)"/><line x1="480" y1="140" x2="500" y2="152" class="arr" marker-end="url(#arr)"/>
  <g class="n-blue"><rect x="80" y="152" width="220" height="26" rx="5"/><text class="ts" x="190" y="165" text-anchor="middle" dominant-baseline="central">New conn → full_state</text></g>
  <g class="n-blue"><rect x="400" y="152" width="220" height="26" rx="5"/><text class="ts" x="510" y="165" text-anchor="middle" dominant-baseline="central">Existing → graph_update delta</text></g>
  <line x1="340" y1="180" x2="340" y2="210" class="arr" marker-end="url(#arr)"/>
  <text class="ts" x="355" y="198" text-anchor="start">WebSocket + HTTP poll fallback</text>
  <g class="n-purple"><rect x="40" y="210" width="600" height="156" rx="12"/><text class="th" x="340" y="230" text-anchor="middle" dominant-baseline="central">Browser (:8384)</text></g>
  <g class="n-amber"><rect x="68" y="244" width="130" height="44" rx="6"/><text class="th" x="133" y="260" text-anchor="middle" dominant-baseline="central">graph.js</text><text class="ts" x="133" y="276" text-anchor="middle" dominant-baseline="central">sigma + FA2</text></g>
  <g class="n-teal"><rect x="214" y="244" width="130" height="44" rx="6"/><text class="th" x="279" y="260" text-anchor="middle" dominant-baseline="central">ui.js</text><text class="ts" x="279" y="276" text-anchor="middle" dominant-baseline="central">Sidebar + detail</text></g>
  <g class="n-blue"><rect x="360" y="244" width="120" height="44" rx="6"/><text class="th" x="420" y="260" text-anchor="middle" dominant-baseline="central">ws.js</text><text class="ts" x="420" y="276" text-anchor="middle" dominant-baseline="central">Reconnect</text></g>
  <g class="n-gray"><rect x="496" y="244" width="120" height="44" rx="6"/><text class="th" x="556" y="260" text-anchor="middle" dominant-baseline="central">node-display</text><text class="ts" x="556" y="276" text-anchor="middle" dominant-baseline="central">Labels + types</text></g>
  <g class="n-gray"><rect x="68" y="302" width="90" height="24" rx="5"/><text class="ts" x="113" y="314" text-anchor="middle" dominant-baseline="central">Drag+hover</text></g>
  <g class="n-gray"><rect x="170" y="302" width="100" height="24" rx="5"/><text class="ts" x="220" y="314" text-anchor="middle" dominant-baseline="central">Path highlight</text></g>
  <g class="n-gray"><rect x="282" y="302" width="100" height="24" rx="5"/><text class="ts" x="332" y="314" text-anchor="middle" dominant-baseline="central">Hull overlays</text></g>
  <g class="n-gray"><rect x="394" y="302" width="80" height="24" rx="5"/><text class="ts" x="434" y="314" text-anchor="middle" dominant-baseline="central">Minimap</text></g>
  <g class="n-gray"><rect x="486" y="302" width="100" height="24" rx="5"/><text class="ts" x="536" y="314" text-anchor="middle" dominant-baseline="central">SVG export</text></g>
  <g class="n-amber"><rect x="68" y="338" width="160" height="22" rx="5"/><text class="ts" x="148" y="349" text-anchor="middle" dominant-baseline="central">New nodes pulse 2s</text></g>
  <g class="n-amber"><rect x="242" y="338" width="180" height="22" rx="5"/><text class="ts" x="332" y="349" text-anchor="middle" dominant-baseline="central">Pin-and-resume on delta</text></g>`
  },

  {
    name: 'service-decomposition',
    viewBox: '0 0 680 460',
    body: `
  <g class="n-amber"><rect x="200" y="10" width="280" height="36" rx="7"/><text class="th" x="340" y="28" text-anchor="middle" dominant-baseline="central">GraphEngine (thin facade)</text></g>
  <line x1="340" y1="46" x2="340" y2="64" class="arr" marker-end="url(#arr)"/>
  <g class="n-gray"><rect x="100" y="64" width="480" height="44" rx="8"/><text class="th" x="340" y="80" text-anchor="middle" dominant-baseline="central">EngineContext (shared mutable state)</text><text class="ts" x="340" y="96" text-anchor="middle" dominant-baseline="central">graph, config, rules, agents, activity log, callbacks, coldStore</text></g>
  <line x1="130" y1="108" x2="130" y2="126" class="arr" marker-end="url(#arr)"/><line x1="270" y1="108" x2="270" y2="126" class="arr" marker-end="url(#arr)"/><line x1="410" y1="108" x2="410" y2="126" class="arr" marker-end="url(#arr)"/><line x1="540" y1="108" x2="540" y2="126" class="arr" marker-end="url(#arr)"/>
  <g class="n-teal"><rect x="68" y="126" width="130" height="44" rx="6"/><text class="th" x="133" y="142" text-anchor="middle" dominant-baseline="central">Inference engine</text><text class="ts" x="133" y="158" text-anchor="middle" dominant-baseline="central">22 rules, selectors</text></g>
  <g class="n-blue"><rect x="210" y="126" width="120" height="44" rx="6"/><text class="th" x="270" y="142" text-anchor="middle" dominant-baseline="central">Frontier</text><text class="ts" x="270" y="158" text-anchor="middle" dominant-baseline="central">5 item types</text></g>
  <g class="n-purple"><rect x="342" y="126" width="130" height="44" rx="6"/><text class="th" x="407" y="142" text-anchor="middle" dominant-baseline="central">Path analyzer</text><text class="ts" x="407" y="158" text-anchor="middle" dominant-baseline="central">BFS, objectives</text></g>
  <g class="n-coral"><rect x="484" y="126" width="140" height="44" rx="6"/><text class="th" x="554" y="142" text-anchor="middle" dominant-baseline="central">State persistence</text><text class="ts" x="554" y="158" text-anchor="middle" dominant-baseline="central">Atomic write</text></g>
  <text class="th" x="340" y="196" text-anchor="middle" dominant-baseline="central">Supporting services</text>
  <g class="n-gray"><rect x="44" y="210" width="120" height="36" rx="5"/><text class="ts" x="104" y="228" text-anchor="middle" dominant-baseline="central">Identity resolution</text></g>
  <g class="n-gray"><rect x="176" y="210" width="120" height="36" rx="5"/><text class="ts" x="236" y="228" text-anchor="middle" dominant-baseline="central">Identity reconcile</text></g>
  <g class="n-gray"><rect x="308" y="210" width="100" height="36" rx="5"/><text class="ts" x="358" y="228" text-anchor="middle" dominant-baseline="central">Cold store</text></g>
  <g class="n-gray"><rect x="420" y="210" width="100" height="36" rx="5"/><text class="ts" x="470" y="228" text-anchor="middle" dominant-baseline="central">Graph health</text></g>
  <g class="n-gray"><rect x="532" y="210" width="100" height="36" rx="5"/><text class="ts" x="582" y="228" text-anchor="middle" dominant-baseline="central">Graph schema</text></g>
  <text class="th" x="340" y="272" text-anchor="middle" dominant-baseline="central">Operational services</text>
  <g class="n-pink"><rect x="44" y="286" width="100" height="36" rx="5"/><text class="ts" x="94" y="304" text-anchor="middle" dominant-baseline="central">Session mgr</text></g>
  <g class="n-pink"><rect x="156" y="286" width="100" height="36" rx="5"/><text class="ts" x="206" y="304" text-anchor="middle" dominant-baseline="central">Agent mgr</text></g>
  <g class="n-pink"><rect x="268" y="286" width="100" height="36" rx="5"/><text class="ts" x="318" y="304" text-anchor="middle" dominant-baseline="central">Output parsers</text></g>
  <g class="n-pink"><rect x="380" y="286" width="100" height="36" rx="5"/><text class="ts" x="430" y="304" text-anchor="middle" dominant-baseline="central">Skill index</text></g>
  <g class="n-pink"><rect x="492" y="286" width="100" height="36" rx="5"/><text class="ts" x="542" y="304" text-anchor="middle" dominant-baseline="central">Prompt gen</text></g>
  <g class="n-pink"><rect x="44" y="334" width="100" height="36" rx="5"/><text class="ts" x="94" y="352" text-anchor="middle" dominant-baseline="central">Report gen</text></g>
  <g class="n-pink"><rect x="156" y="334" width="100" height="36" rx="5"/><text class="ts" x="206" y="352" text-anchor="middle" dominant-baseline="central">Retrospective</text></g>
  <g class="n-pink"><rect x="268" y="334" width="100" height="36" rx="5"/><text class="ts" x="318" y="352" text-anchor="middle" dominant-baseline="central">Community det.</text></g>
  <g class="n-pink"><rect x="380" y="334" width="100" height="36" rx="5"/><text class="ts" x="430" y="352" text-anchor="middle" dominant-baseline="central">Credential utils</text></g>
  <g class="n-pink"><rect x="492" y="334" width="100" height="36" rx="5"/><text class="ts" x="542" y="352" text-anchor="middle" dominant-baseline="central">Process tracker</text></g>
  <text class="th" x="340" y="396" text-anchor="middle" dominant-baseline="central">Transport + UI</text>
  <g class="n-blue"><rect x="68" y="410" width="160" height="36" rx="6"/><text class="ts" x="148" y="428" text-anchor="middle" dominant-baseline="central">stdio (MCP default)</text></g>
  <g class="n-blue"><rect x="248" y="410" width="180" height="36" rx="6"/><text class="ts" x="338" y="428" text-anchor="middle" dominant-baseline="central">HTTP/SSE (streamable)</text></g>
  <g class="n-blue"><rect x="448" y="410" width="190" height="36" rx="6"/><text class="ts" x="543" y="428" text-anchor="middle" dominant-baseline="central">Dashboard (WS + sigma.js)</text></g>`
  },
];

// ── Generate ────────────────────────────────────────────────
for (const { name, viewBox, body } of diagrams) {
  for (const theme of ['dark', 'light']) {
    const style = theme === 'dark' ? DARK_STYLE : LIGHT_STYLE;
    const bg    = theme === 'dark' ? DARK_BG : LIGHT_BG;
    // Connector lines use hardcoded #6b7280 for merge lines — remap for light
    let svgBody = body;
    if (theme === 'light') {
      svgBody = svgBody.replace(/#6b7280/g, '#94a3b8');
    }
    const svg = [
      `<svg viewBox="${viewBox}" xmlns="http://www.w3.org/2000/svg">`,
      style,
      `<rect width="100%" height="100%" fill="${bg}" rx="6"/>`,
      MARKER,
      svgBody,
      `</svg>`,
      '',
    ].join('\n');

    const file = path.join(ASSETS, `${name}-${theme}.svg`);
    fs.writeFileSync(file, svg);
    console.log(`wrote ${file}`);
  }
}
console.log(`\nDone — ${diagrams.length * 2} SVGs in docs/assets/`);
