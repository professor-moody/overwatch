import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  RECOMMENDED_NODE_MAJOR,
  SUPPORTED_NODE_MAJORS,
  classifyNodeVersion,
  parseNodeMajor,
} from '../../scripts/node-runtime.mjs';

describe('Node runtime support contract', () => {
  it('qualifies exactly Node 20, 22, and 24', () => {
    expect(SUPPORTED_NODE_MAJORS).toEqual([20, 22, 24]);
    expect(RECOMMENDED_NODE_MAJOR).toBe(24);

    for (const version of ['20.0.0', 'v20.19.5', '22.18.0', 'v24.11.1']) {
      expect(classifyNodeVersion(version)).toMatchObject({ supported: true });
    }
    for (const version of ['18.20.0', '21.7.3', '23.11.1', '25.0.0', '26.0.0']) {
      expect(classifyNodeVersion(version)).toMatchObject({
        supported: false,
        recommended_major: 24,
        supported_majors: [20, 22, 24],
      });
    }
  });

  it('parses injected version strings without reading the running process', () => {
    expect(parseNodeMajor('v24.18.0')).toBe(24);
    expect(parseNodeMajor('22')).toBe(22);
    expect(parseNodeMajor('20.11.1-pre')).toBe(20);
    expect(parseNodeMajor('')).toBeNull();
    expect(parseNodeMajor('not-a-version')).toBeNull();
    expect(classifyNodeVersion('not-a-version')).toMatchObject({ major: null, supported: false });
  });

  it('keeps package metadata and the full runtime matrix aligned', () => {
    const packageJson = JSON.parse(readFileSync(resolve('package.json'), 'utf8')) as {
      engines: { node: string };
      files: string[];
    };
    const workflow = readFileSync(resolve('.github/workflows/ci.yml'), 'utf8');
    const doctor = readFileSync(resolve('scripts/doctor.mjs'), 'utf8');
    const lifecycle = readFileSync(resolve('scripts/daemon-lifecycle.mjs'), 'utf8');

    expect(packageJson.engines.node).toBe('>=20 <21 || >=22 <23 || >=24 <25');
    expect(packageJson.files).toContain('scripts/node-runtime.mjs');
    expect(packageJson.files).toContain('scripts/node-runtime.d.mts');
    expect(workflow).toContain('node-version: [20, 22, 24]');
    expect(workflow).toMatch(/supported-runtime-matrix:[\s\S]*npm run test:source[\s\S]*npm run test:dashboard-dom[\s\S]*npm run build[\s\S]*npm run test:lifecycle/u);
    expect(doctor).toContain("classifyNodeVersion(process.versions.node)");
    expect(doctor).toContain('Install Node.js ${nodeRuntime.recommended_major}.');
    expect(lifecycle).not.toContain('classifyNodeVersion');
  });
});
