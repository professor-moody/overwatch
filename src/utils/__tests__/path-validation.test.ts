import { describe, it, expect } from 'vitest';
import { resolve, sep } from 'path';
import { validateFilePath } from '../path-validation.js';

describe('validateFilePath', () => {
  it('resolves a simple relative path', () => {
    const result = validateFilePath('foo/bar.txt');
    expect(result).toBe(resolve('foo/bar.txt'));
  });

  it('resolves an absolute path', () => {
    const result = validateFilePath('/tmp/test.txt');
    expect(result).toBe('/tmp/test.txt');
  });

  it('rejects empty string', () => {
    expect(() => validateFilePath('')).toThrow('must not be empty');
  });

  it('rejects whitespace-only string', () => {
    expect(() => validateFilePath('   ')).toThrow('must not be empty');
  });

  it('rejects null bytes', () => {
    expect(() => validateFilePath('/tmp/test\0.txt')).toThrow('null bytes');
  });

  it('enforces baseDir containment', () => {
    expect(() => validateFilePath('/etc/passwd', { baseDir: '/tmp' })).toThrow('must be within');
  });

  it('rejects path traversal out of baseDir', () => {
    expect(() => validateFilePath('/tmp/../etc/passwd', { baseDir: '/tmp' })).toThrow('must be within');
  });

  it('allows path within baseDir', () => {
    const result = validateFilePath('/tmp/subdir/file.txt', { baseDir: '/tmp' });
    expect(result).toBe('/tmp/subdir/file.txt');
  });

  it('allows path equal to baseDir', () => {
    const result = validateFilePath('/tmp', { baseDir: '/tmp' });
    expect(result).toBe('/tmp');
  });
});
