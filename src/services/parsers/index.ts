// Parsers barrel — re-exports all individual parsers and provides the
// PARSERS registry, parseOutput() entry point, and getSupportedParsers().

import type { Finding, ParseContext } from '../../types.js';

export { parseNmapXml, parseNmapGrepable, parseNmap } from './nmap.js';
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
export { parseJwtTool } from './jwt-tool.js';
export { parseRoadrecon } from './roadrecon.js';
export { parseOkta } from './okta.js';
export { parseMicroBurst } from './microburst.js';
export { parseAadInternals } from './aadinternals.js';
export { parseEvilginx } from './evilginx.js';
export { parseGitHubActionsOidc } from './github-actions-oidc.js';
export { parseGitlabCiOidc } from './gitlab-ci-oidc.js';
export { parseCircleciOidc } from './circleci-oidc.js';
export { parseTokenReplayMsGraph } from './token-replay-msgraph.js';
export { parseTokenReplayAwsSts } from './token-replay-awssts.js';
export { parseTokenReplayOkta } from './token-replay-okta.js';
export { parseTokenReplayGitHub } from './token-replay-github.js';
export { parseAwsStsIdentity } from './aws-sts-identity.js';
export { parseAwsIamSummary } from './aws-iam-summary.js';
export { parseGhApiOrgs } from './gh-api-orgs.js';
export { parseGhApiRepos } from './gh-api-repos.js';
export { parseGhApiSecrets } from './gh-api-secrets.js';
export { parseGhApiBranchProtection } from './gh-api-branch-protection.js';
export { parseGhApiDeployKeys } from './gh-api-deploy-keys.js';
export { parseMsGraphUsers } from './msgraph-users.js';
export { parseMsGraphApplications } from './msgraph-applications.js';
export { parseMsGraphServicePrincipals } from './msgraph-serviceprincipals.js';
export { parseMsGraphGroups } from './msgraph-groups.js';
export { parseNessus } from './nessus.js';
// OSINT external-recon parsers (Phase 2C).
export { parseCrtSh } from './crtsh.js';
export { parseSubfinder } from './subfinder.js';
export { parseWhois } from './whois.js';
export { parseAmass } from './amass.js';
export { parseDnsx } from './dnsx.js';
export { parseHttpx } from './httpx.js';
export { parseTestWebappCredential } from './test-webapp-credential.js';
export { parseTrufflehog, parseSecretfinder, parseLinkfinder } from './js-secrets.js';
export { parseOpenapi, parseGraphqlSchema } from './api-schema.js';
export { parseTheHarvester } from './theharvester.js';

import { parseNmapXml, parseNmapGrepable, parseNmap } from './nmap.js';
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
import { parseJwtTool } from './jwt-tool.js';
import { parseRoadrecon } from './roadrecon.js';
import { parseOkta } from './okta.js';
import { parseMicroBurst } from './microburst.js';
import { parseAadInternals } from './aadinternals.js';
import { parseEvilginx } from './evilginx.js';
import { parseGitHubActionsOidc } from './github-actions-oidc.js';
import { parseGitlabCiOidc } from './gitlab-ci-oidc.js';
import { parseCircleciOidc } from './circleci-oidc.js';
import { parseTokenReplayMsGraph } from './token-replay-msgraph.js';
import { parseTokenReplayAwsSts } from './token-replay-awssts.js';
import { parseTokenReplayOkta } from './token-replay-okta.js';
import { parseTokenReplayGitHub } from './token-replay-github.js';
import { parseAwsStsIdentity } from './aws-sts-identity.js';
import { parseAwsIamSummary } from './aws-iam-summary.js';
import { parseGhApiOrgs } from './gh-api-orgs.js';
import { parseGhApiRepos } from './gh-api-repos.js';
import { parseGhApiSecrets } from './gh-api-secrets.js';
import { parseGhApiBranchProtection } from './gh-api-branch-protection.js';
import { parseGhApiDeployKeys } from './gh-api-deploy-keys.js';
import { parseMsGraphUsers } from './msgraph-users.js';
import { parseMsGraphApplications } from './msgraph-applications.js';
import { parseMsGraphServicePrincipals } from './msgraph-serviceprincipals.js';
import { parseMsGraphGroups } from './msgraph-groups.js';
import { parseNessus } from './nessus.js';
import { parseCrtSh } from './crtsh.js';
import { parseSubfinder } from './subfinder.js';
import { parseWhois } from './whois.js';
import { parseAmass } from './amass.js';
import { parseDnsx } from './dnsx.js';
import { parseHttpx } from './httpx.js';
import { parseTestWebappCredential } from './test-webapp-credential.js';
import { parseTrufflehog, parseSecretfinder, parseLinkfinder } from './js-secrets.js';
import { parseOpenapi, parseGraphqlSchema } from './api-schema.js';
import { parseTheHarvester } from './theharvester.js';

const PARSERS: Record<string, (output: string, agentId?: string, context?: ParseContext) => Finding> = {
  'nmap': parseNmap,
  'nmap-xml': parseNmapXml,
  'nmap-gnmap': parseNmapGrepable,
  'nmap-grepable': parseNmapGrepable,
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
  // Phase 2 (enterprise readiness): SSO / cloud-identity parsers.
  'jwt-tool': parseJwtTool,
  'jwt': parseJwtTool,
  'jwt_tool': parseJwtTool,
  'oidc-token': parseJwtTool,
  'roadrecon': parseRoadrecon,
  'roadtools': parseRoadrecon,
  'okta': parseOkta,
  'okta-cli': parseOkta,
  'microburst': parseMicroBurst,
  'micro-burst': parseMicroBurst,
  'get-azpasswords': parseMicroBurst,
  'aadinternals': parseAadInternals,
  'aad-internals': parseAadInternals,
  'evilginx': parseEvilginx,
  'evilginx2': parseEvilginx,
  // CI / OIDC federation parsers (Phase 5).
  'github-actions-oidc': parseGitHubActionsOidc,
  'gha-oidc': parseGitHubActionsOidc,
  'aws-iam-trust-gha': parseGitHubActionsOidc,
  'gitlab-ci-oidc': parseGitlabCiOidc,
  'gitlab-ci': parseGitlabCiOidc,
  'circleci-oidc': parseCircleciOidc,
  'circleci': parseCircleciOidc,
  // Track D: token-replay response parsers (per provider).
  'token_replay_msgraph': parseTokenReplayMsGraph,
  'token_replay_awssts': parseTokenReplayAwsSts,
  'token_replay_okta': parseTokenReplayOkta,
  'token_replay_github': parseTokenReplayGitHub,
  // A.1 — AWS playbook step parsers.
  'aws-sts-identity': parseAwsStsIdentity,
  'aws-sts-get-caller-identity': parseAwsStsIdentity,
  'aws-iam-summary': parseAwsIamSummary,
  'aws-iam-get-account-summary': parseAwsIamSummary,
  // A.2 — GitHub playbook step parsers.
  'gh-api-orgs': parseGhApiOrgs,
  'gh-api-repos': parseGhApiRepos,
  'gh-api-secrets': parseGhApiSecrets,
  'gh-api-actions-secrets': parseGhApiSecrets,
  'gh-api-branch-protection': parseGhApiBranchProtection,
  'gh-api-deploy-keys': parseGhApiDeployKeys,
  // A.4 — Entra/Azure playbook step parsers.
  'msgraph-users': parseMsGraphUsers,
  'msgraph-applications': parseMsGraphApplications,
  'msgraph-apps': parseMsGraphApplications,
  'msgraph-serviceprincipals': parseMsGraphServicePrincipals,
  'msgraph-sp': parseMsGraphServicePrincipals,
  'msgraph-groups': parseMsGraphGroups,
  // Nessus vulnerability scanner
  'nessus': parseNessus,
  'nessus-xml': parseNessus,
  '.nessus': parseNessus,
  // OSINT external-recon parsers (Phase 2C).
  'crtsh': parseCrtSh,
  'crt.sh': parseCrtSh,
  'crt-sh': parseCrtSh,
  'subfinder': parseSubfinder,
  'whois': parseWhois,
  'amass': parseAmass,
  'dnsx': parseDnsx,
  'httpx': parseHttpx,
  'theharvester': parseTheHarvester,
  // Web track: test_webapp_credential live auth-attempt response parser.
  'test_webapp_credential': parseTestWebappCredential,
  // Web track: JS secret + endpoint scanners.
  'trufflehog': parseTrufflehog,
  'secretfinder': parseSecretfinder,
  'linkfinder': parseLinkfinder,
  // Web track: API-schema enumeration.
  'openapi': parseOpenapi,
  'swagger': parseOpenapi,
  'graphql': parseGraphqlSchema,
  'graphql_introspection': parseGraphqlSchema,
};

export function getSupportedParsers(): string[] {
  return Object.keys(PARSERS);
}

/**
 * Per-parser map of exit codes that should still be treated as a successful
 * run when the upstream tool routinely uses non-zero exits to communicate
 * "found nothing" or "partial result" rather than a real failure.
 *
 * Keys are normalized parser aliases (the keys of `PARSERS`). Any exit code
 * not listed here is interpreted as a hard failure for the purposes of
 * action lifecycle classification, but the runner still attempts to parse
 * the captured output and tags the resulting finding `partial: true`.
 *
 * Examples of well-known non-zero "ok" exit codes:
 *   - nuclei      → 1 means "no matches" (all templates ran cleanly)
 *   - sqlmap      → 1 means "not vulnerable"
 *   - gobuster    → 1 means "no results"
 *   - feroxbuster → 1 means "no results"
 *   - ffuf        → 1 means "no matches"
 *   - nikto       → 1 means "scan completed, nothing found"
 *   - wpscan      → 4 means "no findings"
 */
export const PARSER_ACCEPTABLE_EXIT_CODES: Record<string, ReadonlySet<number>> = {
  nuclei: new Set([0, 1]),
  sqlmap: new Set([0, 1]),
  gobuster: new Set([0, 1]),
  feroxbuster: new Set([0, 1]),
  ffuf: new Set([0, 1]),
  dirbuster: new Set([0, 1]),
  nikto: new Set([0, 1]),
  wpscan: new Set([0, 4]),
  // trufflehog exits 183 when it finds verified secrets (with --fail).
  trufflehog: new Set([0, 183]),
};

export function isAcceptableParserExit(toolName: string, exitCode: number | null): boolean {
  if (exitCode === null) return false;
  const allowed = PARSER_ACCEPTABLE_EXIT_CODES[toolName.toLowerCase()];
  if (!allowed) return exitCode === 0;
  return allowed.has(exitCode);
}

/**
 * Sentinel prefix on Finding.raw_output indicating the dispatched parser
 * threw an uncaught exception. Callers should check `isParserError(finding)`
 * before treating the empty nodes/edges as "no data" so the operator's LLM
 * sees an explicit parser failure rather than a misleading "no data" reply.
 */
export const PARSE_ERROR_RAW_PREFIX = 'PARSER_ERROR:';

/**
 * Test-only: register a parser implementation under a name. Returns a
 * disposer that removes the registration. Use only in tests — production
 * code should not mutate the PARSERS registry at runtime.
 */
export function __registerParserForTest(
  name: string,
  fn: (output: string, agentId?: string, context?: ParseContext) => Finding,
): () => void {
  const key = name.toLowerCase();
  const previous = PARSERS[key];
  PARSERS[key] = fn;
  return () => {
    if (previous) PARSERS[key] = previous; else delete PARSERS[key];
  };
}

export function isParserError(finding: Finding | null | undefined): boolean {
  return !!finding && typeof finding.raw_output === 'string'
    && finding.raw_output.startsWith(PARSE_ERROR_RAW_PREFIX);
}

export function parseOutput(toolName: string, output: string, agentId?: string, context?: ParseContext): Finding | null {
  const parser = PARSERS[toolName.toLowerCase()];
  if (!parser) return null;
  try {
    return parser(stripAnsi(output), agentId, context);
  } catch (err) {
    // Fail-loud: surface the parser crash as a Finding with no nodes/edges
    // but with raw_output describing the failure so the operator's LLM sees
    // explicitly which parser threw and can route around it. Returning null
    // here would conflate "parser threw" with "no parser registered", which
    // are different operational signals.
    const message = err instanceof Error ? err.message : String(err);
    const stack = err instanceof Error && err.stack ? err.stack.split('\n').slice(0, 5).join('\n') : '';
    const inputPrefix = output.slice(0, 200);
    return {
      id: `parse-error-${toolName}-${Date.now()}`,
      agent_id: agentId || 'unknown',
      timestamp: new Date().toISOString(),
      tool_name: toolName,
      nodes: [],
      edges: [],
      raw_output: `${PARSE_ERROR_RAW_PREFIX} ${toolName} threw: ${message}\n${stack}\n--- input prefix (200 bytes) ---\n${inputPrefix}`,
    };
  }
}
