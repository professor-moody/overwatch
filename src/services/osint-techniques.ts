// OSINT technique classification for OPSEC (Phase 2B).
//
// PASSIVE techniques query PUBLIC sources (certificate-transparency logs, WHOIS /
// registries, search engines, breach datasets) and never send a packet to the
// target. They are therefore 0-noise and exempt from the engagement's noise
// ceiling and time-window — those constraints exist to limit what the *target's*
// defenders observe, and passive recon is invisible to them.
//
// LIGHT-ACTIVE OSINT (active DNS resolution, HTTP probing — dnsx/httpx) DOES
// contact in-scope assets and is treated as ordinary low-noise work, so it is
// deliberately NOT listed here: it goes through the normal scope + noise path.

export const PASSIVE_TECHNIQUES: ReadonlySet<string> = new Set([
  'crt_sh',          // certificate transparency log search
  'whois',           // domain / IP registration lookup
  'amass_passive',   // amass in passive (no-resolution) mode
  'subfinder',       // passive subdomain sources
  'theharvester',    // email / host harvesting from public sources
  'passive_dns',     // passive DNS aggregators
  'shodan',          // internet-scan datasets (no direct target contact)
  'github_dork',     // public code / secret search
]);

/** True for OSINT techniques that make NO contact with the target (0 noise). */
export function isPassiveTechnique(technique: string | undefined | null): boolean {
  return !!technique && PASSIVE_TECHNIQUES.has(technique);
}
