import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { checkAllTools, checkToolByName } from '../services/tool-check.js';
import { withErrorBoundary } from './error-boundary.js';

export function registerToolCheckTools(server: McpServer): void {

  // ============================================================
  // Tool: check_tools
  // Detect installed offensive security tools on the system
  // ============================================================
  server.registerTool(
    'check_tools',
    {
      title: 'Check Available Tools',
      description: `Check which offensive security tools are installed on this system.

Returns a list of common pentest tools with their installation status, version, and path.
Useful for planning what techniques are available without trial-and-error.

Tools checked include: nmap, nxc/netexec, certipy, impacket suite,
bloodhound-python, gobuster/feroxbuster, ldapsearch, smbclient, rpcclient,
john, hashcat, responder, enum4linux-ng, kerbrute.`,
      inputSchema: {
        tool_name: z.string().optional().describe('Check a specific tool by name. Omit to check all tools.'),
        tool: z.string().optional().describe('Alias for tool_name'),
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true
      }
    },
    withErrorBoundary('check_tools', async ({ tool_name: rawToolName, tool }) => {
      const tool_name = rawToolName || tool;
      if (tool_name) {
        const result = await checkToolByName(tool_name);
        if (!result) {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: `Unknown tool: ${tool_name}` }, null, 2) }],
            isError: true,
          };
        }
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      const results = await checkAllTools();
      const installed = results.filter(t => t.installed);
      const missing = results.filter(t => !t.installed);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            installed_count: installed.length,
            missing_count: missing.length,
            installed,
            missing: missing.map(t => t.name),
          }, null, 2)
        }],
      };
    })
  );
}
