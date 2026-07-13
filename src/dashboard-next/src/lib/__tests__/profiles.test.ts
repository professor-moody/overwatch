import { describe, it, expect } from 'vitest';
import { ENGAGEMENT_PROFILES, PROFILE_LABELS } from '../profiles';

describe('engagement profiles', () => {
  // These MUST equal the `profile` enum in engagementConfigSchema (src/types.ts):
  // z.enum(['goad_ad','single_host','network','web_app','cloud','hybrid']). A value not
  // in the enum fails config validation on save (400). SettingsPanel used to emit the
  // invalid 'ad'/'webapp' and omit goad_ad/single_host/web_app.
  it('matches the config schema enum (and excludes the old invalid values)', () => {
    expect([...ENGAGEMENT_PROFILES].sort()).toEqual(
      ['cloud', 'goad_ad', 'hybrid', 'network', 'single_host', 'web_app'].sort(),
    );
    expect(ENGAGEMENT_PROFILES).not.toContain('ad');
    expect(ENGAGEMENT_PROFILES).not.toContain('webapp');
  });

  it('has a label for every profile', () => {
    for (const p of ENGAGEMENT_PROFILES) expect(PROFILE_LABELS[p]).toBeTruthy();
  });
});
