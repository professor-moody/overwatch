import { describe, it, expect } from 'vitest';
import { evidenceImageUrl } from '../api';

describe('evidenceImageUrl', () => {
  it('builds a same-origin /api/evidence/<id>/image URL', () => {
    expect(evidenceImageUrl('abc-123')).toBe('/api/evidence/abc-123/image');
  });

  it('url-encodes the evidence id', () => {
    expect(evidenceImageUrl('a/b c')).toBe('/api/evidence/a%2Fb%20c/image');
  });
});
