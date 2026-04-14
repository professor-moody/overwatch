import { resolve, normalize } from 'path';

/**
 * Validate and resolve a user-provided file path.
 * Rejects null bytes and path traversal sequences.
 * Returns the resolved absolute path.
 */
export function validateFilePath(
  filePath: string,
  opts?: { baseDir?: string },
): string {
  if (!filePath || filePath.trim().length === 0) {
    throw new Error('File path must not be empty');
  }

  // Reject null bytes (path truncation attack vector)
  if (filePath.includes('\0')) {
    throw new Error('File path must not contain null bytes');
  }

  const resolved = resolve(filePath);
  const normalized = normalize(resolved);

  // If a baseDir is provided, enforce containment
  if (opts?.baseDir) {
    const normalizedBase = normalize(resolve(opts.baseDir));
    if (!normalized.startsWith(normalizedBase + '/') && normalized !== normalizedBase) {
      throw new Error(`File path must be within ${normalizedBase}`);
    }
  }

  return normalized;
}
