import { describe, expect, it } from 'vitest';
import { compareDashboardBuilds } from '../dashboard-build-compatibility';

const client = 'a'.repeat(64);

describe('dashboard build compatibility', () => {
  it('accepts one exact build fingerprint', () => {
    expect(compareDashboardBuilds(client, client)).toMatchObject({
      compatible: true,
      client_build: client,
      server_build: client,
    });
  });

  it('identifies old tabs and legacy daemons explicitly', () => {
    expect(compareDashboardBuilds('b'.repeat(64), client)).toMatchObject({
      compatible: false,
      message: expect.stringContaining('does not match'),
    });
    expect(compareDashboardBuilds(undefined, client)).toMatchObject({
      compatible: false,
      message: expect.stringContaining('legacy/unknown'),
    });
  });
});
