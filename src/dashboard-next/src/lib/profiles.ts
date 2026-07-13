// Single source of truth for engagement `profile` values shown in the UI.
// These MUST stay in sync with the `profile` enum in engagementConfigSchema
// (src/types.ts) — a value not in that enum fails config validation on save.
export const ENGAGEMENT_PROFILES = ['network', 'goad_ad', 'single_host', 'web_app', 'cloud', 'hybrid'] as const;

export type EngagementProfile = typeof ENGAGEMENT_PROFILES[number];

// Record<string, string> (not Record<EngagementProfile, string>) so callers can index
// with a plain `string` profile value from the wire without a cast.
export const PROFILE_LABELS: Record<string, string> = {
  network: 'Network',
  goad_ad: 'GOAD / AD',
  single_host: 'Single Host',
  web_app: 'Web App',
  cloud: 'Cloud',
  hybrid: 'Hybrid',
};
