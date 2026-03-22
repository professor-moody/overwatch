import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export type McpStdioSession = {
  client: Client;
  transport: StdioClientTransport;
};

export async function startMcpStdioSession(options: {
  command: string;
  args: string[];
  cwd: string;
  env: Record<string, string>;
  clientName: string;
}): Promise<McpStdioSession> {
  const transport = new StdioClientTransport({
    command: options.command,
    args: options.args,
    cwd: options.cwd,
    env: options.env,
    stderr: 'pipe',
  });

  const client = new Client({ name: options.clientName, version: '0.1.0' });
  await client.connect(transport);
  return { client, transport };
}

export async function stopMcpStdioSession(session: McpStdioSession | null): Promise<void> {
  if (!session) return;
  await session.client.close().catch(() => {});
  await session.transport.close().catch(() => {});
}

export async function callJsonTool<T>(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<T> {
  const result = await client.callTool({ name, arguments: args });
  const content = result.content as Array<{ type: string; text: string }>;
  const text = content[0]?.text || '';

  if (result.isError) {
    throw new Error(`Tool ${name} returned error: ${text || 'unknown error'}`);
  }

  return JSON.parse(text) as T;
}
