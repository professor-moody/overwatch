export const SUPPORTED_NODE_MAJORS: readonly [20, 22, 24];
export const RECOMMENDED_NODE_MAJOR: 24;

export interface NodeRuntimeClassification {
  version: string;
  major: number | null;
  supported: boolean;
  recommended_major: 24;
  supported_majors: Array<20 | 22 | 24>;
}

export function parseNodeMajor(version: unknown): number | null;
export function classifyNodeVersion(version: unknown): NodeRuntimeClassification;
