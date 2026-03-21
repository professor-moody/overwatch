import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { checkAllTools, checkToolByName } from '../services/tool-check.js';

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
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true
      }
    },
    async ({ tool_name }) => {
      if (tool_name) {
        const result = checkToolByName(tool_name);
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

      const results = checkAllTools();
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
    }
  );
}
