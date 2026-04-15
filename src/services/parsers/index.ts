// Parsers barrel — re-exports all individual parsers and provides the
// PARSERS registry, parseOutput() entry point, and getSupportedParsers().

import type { Finding, ParseContext } from '../../types.js';

export { parseNmapXml } from './nmap.js';
export { parseNxc } from './nxc.js';
export { parseCertipy } from './certipy.js';
export { parseSecretsdump } from './impacket.js';
export { parseKerbrute } from './kerbrute.js';
export { parseHashcat } from './hashcat.js';
export { parseResponder } from './responder.js';
export { parseLdapsearch } from './ldap.js';
export { parseEnum4linux } from './enum4linux.js';
export { parseRubeus } from './rubeus.js';
export { parseWebDirEnum } from './web-scanners.js';
export { parseLinpeas, stripAnsi } from './linpeas.js';
export { parseNuclei } from './nuclei.js';
export { parseNikto } from './nikto.js';
export { parseTestssl } from './testssl.js';
export { parsePacu, parseProwler, parseEnumerateIam } from './cloud.js';
export { parseScoutSuite } from './scoutsuite.js';
export { parseCloudFox } from './cloudfox.js';
export { parseTerraformState } from './terraform.js';
export { parseBurp } from './burp.js';
export { parseZap } from './zap.js';
export { parseSqlmap } from './sqlmap.js';
export { parseWpscan } from './wpscan.js';
export { parseGetNPUsers, parseGetUserSPNs, parseGetTGT, parseGetST, parseSmbclient, parseWmiexec, parsePsexec } from './impacket-suite.js';

import { parseNmapXml } from './nmap.js';
import { parseNxc } from './nxc.js';
import { parseCertipy } from './certipy.js';
import { parseSecretsdump } from './impacket.js';
import { parseKerbrute } from './kerbrute.js';
import { parseHashcat } from './hashcat.js';
import { parseResponder } from './responder.js';
import { parseLdapsearch } from './ldap.js';
import { parseEnum4linux } from './enum4linux.js';
import { parseRubeus } from './rubeus.js';
import { parseWebDirEnum } from './web-scanners.js';
import { parseLinpeas, stripAnsi } from './linpeas.js';
import { parseNuclei } from './nuclei.js';
import { parseNikto } from './nikto.js';
import { parseTestssl } from './testssl.js';
import { parsePacu, parseProwler, parseEnumerateIam } from './cloud.js';
import { parseScoutSuite } from './scoutsuite.js';
import { parseCloudFox } from './cloudfox.js';
import { parseTerraformState } from './terraform.js';
import { parseBurp } from './burp.js';
import { parseZap } from './zap.js';
import { parseSqlmap } from './sqlmap.js';
import { parseWpscan } from './wpscan.js';
import { parseGetNPUsers, parseGetUserSPNs, parseGetTGT, parseGetST, parseSmbclient, parseWmiexec, parsePsexec } from './impacket-suite.js';

const PARSERS: Record<string, (output: string, agentId?: string, context?: ParseContext) => Finding> = {
  'nmap': parseNmapXml,
  'nmap-xml': parseNmapXml,
  'netexec': parseNxc,
  'nxc': parseNxc,
  'certipy': parseCertipy,
  'secretsdump': parseSecretsdump,
  'impacket-secretsdump': parseSecretsdump,
  'kerbrute': parseKerbrute,
  'hashcat': parseHashcat,
  'responder': parseResponder,
  'ldapsearch': parseLdapsearch,
  'ldapdomaindump': parseLdapsearch,
  'ldap': parseLdapsearch,
  'enum4linux': parseEnum4linux,
  'enum4linux-ng': parseEnum4linux,
  'rubeus': parseRubeus,
  'gobuster': parseWebDirEnum,
  'feroxbuster': parseWebDirEnum,
  'ffuf': parseWebDirEnum,
  'dirbuster': parseWebDirEnum,
  'linpeas': parseLinpeas,
  'linenum': parseLinpeas,
  'linpeas.sh': parseLinpeas,
  'nuclei': parseNuclei,
  'nikto': parseNikto,
  'testssl': parseTestssl,
  'testssl.sh': parseTestssl,
  'sslscan': parseTestssl,
  'pacu': parsePacu,
  'prowler': parseProwler,
  'scoutsuite': parseScoutSuite,
  'scout-suite': parseScoutSuite,
  'cloudfox': parseCloudFox,
  'cloud-fox': parseCloudFox,
  'terraform': parseTerraformState,
  'terraform-state': parseTerraformState,
  'enumerate-iam': parseEnumerateIam,
  'enumerate_iam': parseEnumerateIam,
  'burp': parseBurp,
  'burp-suite': parseBurp,
  'zap': parseZap,
  'owasp-zap': parseZap,
  'sqlmap': parseSqlmap,
  'wpscan': parseWpscan,
  'getnpusers': parseGetNPUsers,
  'impacket-getnpusers': parseGetNPUsers,
  'getuserspns': parseGetUserSPNs,
  'impacket-getuserspns': parseGetUserSPNs,
  'gettgt': parseGetTGT,
  'impacket-gettgt': parseGetTGT,
  'getst': parseGetST,
  'impacket-getst': parseGetST,
  'smbclient': parseSmbclient,
  'impacket-smbclient': parseSmbclient,
  'wmiexec': parseWmiexec,
  'impacket-wmiexec': parseWmiexec,
  'psexec': parsePsexec,
  'impacket-psexec': parsePsexec,
};

export function getSupportedParsers(): string[] {
  return Object.keys(PARSERS);
}

export function parseOutput(toolName: string, output: string, agentId?: string, context?: ParseContext): Finding | null {
  const parser = PARSERS[toolName.toLowerCase()];
  if (!parser) return null;
  return parser(stripAnsi(output), agentId, context);
}
