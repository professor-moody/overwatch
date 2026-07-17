import { afterAll, afterEach, beforeEach, vi } from 'vitest';
import { cleanupRegisteredTestSandboxes } from './test-sandbox.js';

let environmentBeforeTest: NodeJS.ProcessEnv;
let workingDirectoryBeforeTest: string;

function restoreEnvironment(snapshot: NodeJS.ProcessEnv): void {
  for (const key of Object.keys(process.env)) {
    if (!(key in snapshot)) delete process.env[key];
  }
  for (const [key, value] of Object.entries(snapshot)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

beforeEach(() => {
  environmentBeforeTest = { ...process.env };
  workingDirectoryBeforeTest = process.cwd();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  restoreEnvironment(environmentBeforeTest);
  try {
    process.chdir(workingDirectoryBeforeTest);
  } catch (error) {
    throw new Error(
      `Failed to restore the test working directory ${workingDirectoryBeforeTest}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
});

afterAll(() => {
  cleanupRegisteredTestSandboxes();
});
