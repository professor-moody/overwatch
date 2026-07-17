import {
  assertArtifactSnapshotUnchanged,
  snapshotSensitiveArtifacts,
} from './artifact-hygiene.js';

export default function setupArtifactHygiene(): () => void {
  const workspaceRoot = process.cwd();
  const before = snapshotSensitiveArtifacts(workspaceRoot);
  return () => {
    const after = snapshotSensitiveArtifacts(workspaceRoot);
    try {
      assertArtifactSnapshotUnchanged(before, after);
    } catch (error) {
      // Vitest currently reports global-teardown errors without always
      // propagating a non-zero status. Preserve the thrown diagnostic and make
      // the residue gate authoritative for local runs and CI.
      process.exitCode = 1;
      throw error;
    }
  };
}
