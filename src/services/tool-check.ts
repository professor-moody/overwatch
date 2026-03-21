// ============================================================
// Tool Availability Health Check
// Detects installed offensive security tools on the system
// ============================================================

import { execSync } from 'child_process';

export interface ToolStatus {
  name: string;
  installed: boolean;
  version?: string;
  path?: string;
}

const TOOL_CHECKS: Array<{ name: string; command: string; versionFlag: string }> = [
  { name: 'nmap', command: 'nmap', versionFlag: '--version' },
  { name: 'crackmapexec', command: 'crackmapexec', versionFlag: '--version' },
  { name: 'netexec', command: 'nxc', versionFlag: '--version' },
  { name: 'certipy', command: 'certipy', versionFlag: '--version' },
  { name: 'impacket-secretsdump', command: 'impacket-secretsdump', versionFlag: '-h' },
  { name: 'impacket-psexec', command: 'impacket-psexec', versionFlag: '-h' },
  { name: 'impacket-wmiexec', command: 'impacket-wmiexec', versionFlag: '-h' },
  { name: 'impacket-getTGT', command: 'impacket-getTGT', versionFlag: '-h' },
  { name: 'bloodhound-python', command: 'bloodhound-python', versionFlag: '--version' },
  { name: 'gobuster', command: 'gobuster', versionFlag: 'version' },
  { name: 'feroxbuster', command: 'feroxbuster', versionFlag: '--version' },
  { name: 'ldapsearch', command: 'ldapsearch', versionFlag: '-VV' },
  { name: 'smbclient', command: 'smbclient', versionFlag: '--version' },
  { name: 'rpcclient', command: 'rpcclient', versionFlag: '--version' },
  { name: 'john', command: 'john', versionFlag: '--version' },
  { name: 'hashcat', command: 'hashcat', versionFlag: '--version' },
  { name: 'responder', command: 'responder', versionFlag: '--version' },
  { name: 'enum4linux-ng', command: 'enum4linux-ng', versionFlag: '--version' },
  { name: 'kerbrute', command: 'kerbrute', versionFlag: 'version' },
  { name: 'python3', command: 'python3', versionFlag: '--version' },
];

function checkTool(tool: { name: string; command: string; versionFlag: string }): ToolStatus {
  try {
    // Check if command exists
    const whichResult = execSync(`which ${tool.command} 2>/dev/null`, { encoding: 'utf-8', timeout: 5000 }).trim();
    if (!whichResult) {
      return { name: tool.name, installed: false };
    }

    // Try to get version
    let version: string | undefined;
    try {
      const output = execSync(`${tool.command} ${tool.versionFlag} 2>&1`, {
        encoding: 'utf-8',
        timeout: 5000,
      }).trim();
      // Extract first line that looks like a version
      const lines = output.split('\n');
      const versionLine = lines.find(l => /\d+\.\d+/.test(l));
      if (versionLine) {
        version = versionLine.slice(0, 120).trim();
      }
    } catch {
      // Command exists but version flag failed — still installed
    }

    return { name: tool.name, installed: true, version, path: whichResult };
  } catch {
    return { name: tool.name, installed: false };
  }
}

export function checkAllTools(): ToolStatus[] {
  return TOOL_CHECKS.map(checkTool);
}

export function checkToolByName(name: string): ToolStatus | null {
  const tool = TOOL_CHECKS.find(t => t.name === name);
  if (!tool) return null;
  return checkTool(tool);
}
