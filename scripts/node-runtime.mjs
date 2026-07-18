export const SUPPORTED_NODE_MAJORS = Object.freeze([20, 22, 24]);
export const RECOMMENDED_NODE_MAJOR = 24;

/** Parse the major from either process.versions.node ("24.1.0") or
 * process.version ("v24.1.0") without consulting global process state. */
export function parseNodeMajor(version) {
  const match = /^v?(\d+)(?:\.|$)/u.exec(String(version ?? '').trim());
  if (!match) return null;
  const major = Number(match[1]);
  return Number.isSafeInteger(major) ? major : null;
}
/** Pure support classification so every known and future major can be tested
 * on one development runtime. Package metadata and doctor are the enforcement
 * boundary; ordinary daemon startup intentionally does not call this helper. */
export function classifyNodeVersion(version) {
  const major = parseNodeMajor(version);
  const supported = major !== null && SUPPORTED_NODE_MAJORS.includes(major);
  return {
    version: String(version ?? ''),
    major,
    supported,
    recommended_major: RECOMMENDED_NODE_MAJOR,
    supported_majors: [...SUPPORTED_NODE_MAJORS],
  };
}
