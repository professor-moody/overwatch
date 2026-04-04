import type { Finding, NodeType, ParseContext } from '../../types.js';
import { v4 as uuidv4 } from 'uuid';

// --- Linpeas / LinEnum Parser ---

// Known dangerous SUID binaries (GTFOBins intersection)
const DANGEROUS_SUID_BINARIES = new Set([
  'python', 'python2', 'python3', 'perl', 'ruby', 'bash', 'sh', 'dash', 'zsh',
  'env', 'find', 'nmap', 'vim', 'vi', 'less', 'more', 'awk', 'gawk', 'nawk',
  'sed', 'cp', 'mv', 'dd', 'tar', 'zip', 'gcc', 'make', 'strace', 'ltrace',
  'gdb', 'node', 'php', 'lua', 'tclsh', 'wish', 'expect', 'docker',
  'pkexec', 'doas', 'mount', 'umount', 'screen', 'tmux',
]);

export function stripAnsi(text: string): string {
  return text.replace(/\x1B\[[0-9;]*[A-Za-z]/g, '').replace(/\x1B\][^\x07]*\x07/g, '');
}

export function parseLinpeas(output: string, agentId: string = 'linpeas-parser', context?: ParseContext): Finding {
  const nodes: Finding['nodes'] = [];
  const edges: Finding['edges'] = [];
  const now = new Date().toISOString();
  const clean = stripAnsi(output);
  const lines = clean.split('\n');

  // Try to extract hostname from linpeas header if no context
  let resolvedHostId = context?.source_host;
  if (!resolvedHostId) {
    const headerLines = lines.slice(0, 30).join('\n');
    const hostnameMatch = headerLines.match(/Hostname:\s*(\S+)/i) ||
                           headerLines.match(/hostname[=:]\s*(\S+)/i) ||
                           headerLines.match(/uname.*\s(\S+)\s/);
    if (hostnameMatch) {
      resolvedHostId = `host-${hostnameMatch[1].toLowerCase().replace(/[^a-z0-9-]/g, '-')}`;
    }
  }
  const hostNodeId = resolvedHostId || `host-linpeas-${uuidv4().slice(0, 8)}`;
  const hostProps: Record<string, unknown> = {
    id: hostNodeId,
    type: 'host' as NodeType,
    label: context?.source_host ? hostNodeId : 'linpeas-target',
    discovered_by: agentId,
    discovered_at: now,
    os: 'Linux',
  };
  if (!context?.source_host) {
    hostProps.confidence = 0.9;
    if (!resolvedHostId) {
      hostProps.notes = 'No source host context — manual merge may be needed';
    }
  }

  const DANGEROUS_CAPABILITIES = new Set([
    'cap_setuid', 'cap_sys_admin', 'cap_dac_override',
    'cap_dac_read_search', 'cap_sys_ptrace', 'cap_fowner',
    'cap_sys_module', 'cap_net_admin', 'cap_chown',
  ]);

  const CRON_SYSTEMD_PATHS = [
    '/etc/cron', '/var/spool/cron', '/etc/systemd', '/lib/systemd',
    '/usr/lib/systemd', '/run/systemd',
  ];

  // Section detection
  let currentSection = '';
  const suidBinaries: string[] = [];
  const interestingCapabilities: string[] = [];
  const cronJobs: string[] = [];
  const writablePaths: string[] = [];
  let kernelVersion: string | undefined;
  let dockerSocketAccessible = false;
  let usersEnumerated = false;
  let sudoersNopasswd = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Section headers: linpeas uses box-drawing chars or ═══ delimiters
    if (line.includes('═══') || line.includes('╔══') || line.includes('╚══')) {
      const headerLine = line.replace(/[═╔╚╗╝║│┌┐└┘─]/g, '').trim();
      if (headerLine) currentSection = headerLine.toLowerCase();
      continue;
    }

    // Kernel version
    if (!kernelVersion) {
      const kvMatch = line.match(/Linux version (\S+)/i) || line.match(/^(\d+\.\d+\.\d+[-.\w]*)\s/);
      if (kvMatch) {
        kernelVersion = kvMatch[1];
      }
    }

    // SUID binaries section
    if (currentSection.includes('suid') || currentSection.includes('sgid') || currentSection.includes('permissions')) {
      const suidMatch = line.match(/-[rwxsStT]{9}\s+\d+\s+root\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)/);
      if (suidMatch) {
        const binaryPath = suidMatch[1].trim();
        const binaryName = binaryPath.split('/').pop() || '';
        suidBinaries.push(binaryPath);
        if (DANGEROUS_SUID_BINARIES.has(binaryName.toLowerCase())) {
          hostProps.has_suid_root = true;
        }
      }
      // Also match simpler format: -rwsr-xr-x path
      const simpleSuid = line.match(/-[rwx]{2}s[rwxsStT-]{6}\s+.*?(\/.+)/);
      if (simpleSuid) {
        const binaryPath = simpleSuid[1].trim();
        const binaryName = binaryPath.split('/').pop() || '';
        if (!suidBinaries.includes(binaryPath)) suidBinaries.push(binaryPath);
        if (DANGEROUS_SUID_BINARIES.has(binaryName.toLowerCase())) {
          hostProps.has_suid_root = true;
        }
      }
    }

    // Capabilities section
    if (currentSection.includes('capabilit')) {
      const capMatch = line.match(/(\S+)\s+=\s+(.*)/);
      if (capMatch) {
        interestingCapabilities.push(`${capMatch[1]} = ${capMatch[2]}`);
      }
    }

    // Cron jobs section
    if (currentSection.includes('cron') || currentSection.includes('timer')) {
      if (line.startsWith('/') || line.startsWith('*') || line.match(/^\d+\s/)) {
        cronJobs.push(line);
      }
    }

    // Writable paths
    if (currentSection.includes('writable') || currentSection.includes('interesting')) {
      if (line.startsWith('/') && !line.includes('proc') && !line.includes('/sys/')) {
        writablePaths.push(line);
      }
    }

    // Docker detection
    if (line.includes('/var/run/docker.sock') || line.includes('docker.sock')) {
      dockerSocketAccessible = true;
    }
    if (line.match(/docker\s*:/i) && currentSection.includes('group')) {
      dockerSocketAccessible = true;
    }

    // Sudoers / NOPASSWD detection
    if (currentSection.includes('sudo') || currentSection.includes('sudoers') || line.includes('NOPASSWD')) {
      if (/NOPASSWD/i.test(line) && !line.startsWith('#')) {
        sudoersNopasswd = true;
      }
    }

    // Users section
    if (currentSection.includes('user') || currentSection.includes('passwd')) {
      usersEnumerated = true;
    }
  }

  // Apply collected properties
  if (suidBinaries.length > 0) {
    hostProps.suid_binaries = suidBinaries;
    hostProps.suid_checked = true;
  } else if (currentSection || lines.length > 10) {
    // If we processed content but found no SUID, still mark as checked
    hostProps.suid_checked = true;
  }

  if (interestingCapabilities.length > 0) {
    hostProps.interesting_capabilities = interestingCapabilities;
    hostProps.capabilities_checked = true;
    const hasDangerous = interestingCapabilities.some(cap => {
      const capLower = cap.toLowerCase();
      return Array.from(DANGEROUS_CAPABILITIES).some(dc => capLower.includes(dc));
    });
    if (hasDangerous) {
      hostProps.has_dangerous_capabilities = true;
    }
  } else if (clean.toLowerCase().includes('capabilit')) {
    hostProps.capabilities_checked = true;
  }

  if (cronJobs.length > 0) {
    hostProps.cron_jobs = cronJobs;
    hostProps.cron_checked = true;
  } else if (clean.toLowerCase().includes('cron')) {
    hostProps.cron_checked = true;
  }

  if (writablePaths.length > 0) {
    hostProps.writable_paths = writablePaths;
    const hasWritableCronSystemd = writablePaths.some(p =>
      CRON_SYSTEMD_PATHS.some(prefix => p.startsWith(prefix))
    );
    if (hasWritableCronSystemd) {
      hostProps.writable_cron_or_systemd = true;
    }
  }

  if (sudoersNopasswd) {
    hostProps.sudoers_nopasswd = true;
  }

  if (kernelVersion) {
    hostProps.kernel_version = kernelVersion;
  }

  if (dockerSocketAccessible) {
    hostProps.docker_socket_accessible = true;
  }

  if (usersEnumerated) {
    hostProps.users_enumerated = true;
  }

  nodes.push(hostProps as Finding['nodes'][0]);

  return { id: uuidv4(), agent_id: agentId, timestamp: now, nodes, edges };
}
