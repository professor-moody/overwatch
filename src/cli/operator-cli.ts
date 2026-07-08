#!/usr/bin/env node
// ============================================================
// Overwatch — Operator CLI (`overwatch`)
// ============================================================
// A standalone terminal client over the Overwatch /api surface. Watch and steer
// the same live engagement the model is driving, without going through Claude.
// Usage: overwatch <command> [--json] [--no-color] [--url URL] [--token TOK]

import { resolveClientOptions, createClient, ApiError } from './operator/client.js';
import { READ_COMMANDS, WRITE_COMMANDS, type Command } from './operator/commands.js';
import { setColorEnabled, bold, dim, cyan } from './operator/format.js';
import { isEntrypoint } from './operator/entrypoint.js';

const COMMANDS: Record<string, Command> = { ...READ_COMMANDS, ...WRITE_COMMANDS };

function printUsage(): void {
  const pad = Math.max(...Object.keys(COMMANDS).map(n => n.length));
  const section = (cmds: Record<string, Command>) =>
    Object.keys(cmds).map(n => `  ${cyan(n.padEnd(pad))}  ${cmds[n].summary}`).join('\n');
  console.log(`${bold('overwatch')} — terminal operator CLI for a live Overwatch engagement

${bold('Usage:')} overwatch <command> [options]

${bold('Read:')}
${section(READ_COMMANDS)}

${bold('Operate:')}
${section(WRITE_COMMANDS)}

${bold('Options:')}
  --json             Print raw JSON (for piping to jq); disables color
  --no-color         Disable ANSI color
  --url <url>        API base URL (default: $OVERWATCH_URL or http://127.0.0.1:8384)
  --token <token>    Bearer token for a remote, non-loopback server ($OVERWATCH_DASHBOARD_TOKEN)
  --help             Show this help (or 'overwatch <command> --help')

${dim('The engagement must be running (npm start -- --http, or the demo daemon).')}`);
}

async function main(): Promise<void> {
  const raw = process.argv.slice(2);
  const name = raw[0];

  if (!name || name === '--help' || name === '-h' || name === 'help') {
    printUsage();
    process.exit(0);
  }

  const command = COMMANDS[name];
  if (!command) {
    console.error(`Unknown command: ${name}\n`);
    printUsage();
    process.exit(2);
  }

  const args = raw.slice(1);
  if (args.includes('--help')) {
    console.log(`overwatch ${command.usage ?? name}\n\n  ${command.summary}`);
    process.exit(0);
  }

  const json = args.includes('--json');
  if (json || args.includes('--no-color')) setColorEnabled(false);

  const client = createClient(resolveClientOptions(args));

  try {
    const result = await command.run({ client, args });
    console.log(json ? JSON.stringify(result.data) : result.text);
  } catch (err) {
    if (err instanceof ApiError) {
      console.error(err.message);
      process.exit(err.unreachable ? 2 : 1);
    }
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

// Run main() when executed as a program — including via the `npm link` / global-bin
// symlink (`overwatch …`), where argv[1] is the symlink path, not operator-cli.js.
if (isEntrypoint(process.argv[1], import.meta.url)) {
  void main();
}
