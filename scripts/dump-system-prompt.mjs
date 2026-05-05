#!/usr/bin/env node
// Render the primary system prompt against the local engagement.json
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { GraphEngine } from '../dist/services/graph-engine.js';
import { generateSystemPrompt } from '../dist/services/prompt-generator.js';

const cfgPath = process.argv[2] ?? './engagement.json';
const role = process.argv[3] ?? 'primary';
const config = JSON.parse(readFileSync(resolve(cfgPath), 'utf8'));

const engine = new GraphEngine(config);

// Mirror the real tool table the server registers
const tools = [
  ['get_state', 'Full engagement briefing'],
  ['next_task', 'Filtered frontier candidates'],
  ['query_graph', 'Open-ended graph exploration'],
  ['find_paths', 'Shortest path to objectives'],
  ['validate_action', 'Pre-execution sanity check'],
  ['log_action_event', 'Record action lifecycle'],
  ['parse_output', 'Parse supported tool output'],
  ['report_finding', 'Submit discoveries to graph'],
  ['get_evidence', 'Retrieve evidence blobs'],
  ['register_agent', 'Dispatch a sub-agent'],
  ['dispatch_agents', 'Batch agent registration'],
  ['get_agent_context', 'Scoped view for sub-agents'],
  ['update_agent', 'Mark agent task done/failed'],
  ['dispatch_subnet_agents', 'Per-CIDR agents'],
  ['dispatch_campaign_agents', 'Campaign agents'],
  ['manage_campaign', 'Campaign lifecycle'],
  ['get_skill', 'RAG skill lookup'],
  ['get_history', 'Activity log'],
  ['export_graph', 'Complete graph dump'],
  ['run_lab_preflight', 'Lab readiness'],
  ['run_graph_health', 'Graph integrity checks'],
  ['recompute_objectives', 'Refresh objectives'],
  ['ingest_bloodhound', 'Import BloodHound JSON'],
  ['ingest_azurehound', 'Import AzureHound JSON'],
  ['check_tools', 'Detect tools on PATH'],
  ['track_process', 'Track scan PIDs'],
  ['check_processes', 'Refresh process status'],
  ['suggest_inference_rule', 'Propose inference rules'],
  ['run_retrospective', 'Post-engagement analysis'],
  ['generate_report', 'Client report'],
  ['correct_graph', 'Transactional graph repair'],
  ['open_session', 'Create persistent session'],
  ['write_session', 'Write to session'],
  ['read_session', 'Read from session'],
  ['send_to_session', 'Send + read convenience'],
  ['list_sessions', 'List sessions'],
  ['update_session', 'Session metadata'],
  ['resize_session', 'Resize PTY'],
  ['signal_session', 'Send signal'],
  ['close_session', 'Close session'],
  ['update_scope', 'Adjust engagement scope'],
  ['get_system_prompt', 'Dynamic instructions'],
].map(([name, description]) => ({ name, description }));

const prompt = generateSystemPrompt(engine, tools, { role, include_state: true, include_tools: true });
process.stdout.write(prompt + '\n');
