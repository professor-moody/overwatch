import { describe, expect, it } from 'vitest';
import { ParserContextSchema } from '../types.js';

describe('ParserContextSchema', () => {
  it('preserves every canonical family and nested provider extensions', () => {
    const input = {
      source_credential_id: 'cred-1', source_idp_application_id: 'app-1', cred_user: 'alice',
      tenant_id: 'tenant-1', repo_full_name: 'acme/repo', branch_name: 'main', owner: 'acme',
      cloud_provider: 'aws', cloud_account: '111122223333', aws_account: '111122223333',
      account_id: '111122223333', caller_arn: 'arn:aws:iam::111122223333:user/alice',
      principal_kind: 'user', principal_name: 'alice', cloud_region: 'us-east-1',
      target_cloud_identity_id: 'cloud-1', target_role_arn: 'arn:aws:iam::111122223333:role/R',
      target_id: 'target-1', target_host: 'host.example', target_ip: '10.0.0.1',
      target_url: 'https://host.example', domain: 'example.test', source_host: 'host-1',
      domain_aliases: { EXAMPLE: 'example.test' }, network_zone: 'corp',
      provider_extension: { nested: { values: ['one', 'two'] } },
    };
    expect(ParserContextSchema.parse(input)).toEqual(input);
  });

  it('rejects malformed known fields while allowing unknown extension shapes', () => {
    expect(ParserContextSchema.safeParse({ tenant_id: 42 }).success).toBe(false);
    expect(ParserContextSchema.safeParse({ extension: { any: ['shape'] } }).success).toBe(true);
  });
});
