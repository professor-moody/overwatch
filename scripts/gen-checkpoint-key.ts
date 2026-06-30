#!/usr/bin/env node
// Generate an Ed25519 keypair for signing chain checkpoints.
//
//   npm run gen:checkpoint-key
//
// The SIGNER (the engine that emits checkpoints) sets OVERWATCH_CHECKPOINT_SIGNING_KEY;
// VERIFIERS (auditors) set OVERWATCH_CHECKPOINT_PUBLIC_KEY. Each accepts an inline PEM, a
// file path, or base64-encoded PEM — the base64 forms below are single-line env-settable.
import { generateCheckpointKeypair } from '../src/services/activity-chain.js';

const kp = generateCheckpointKeypair();
const b64 = (pem: string) => Buffer.from(pem, 'utf8').toString('base64');

console.log(`# Ed25519 checkpoint signing keypair
# key id: ${kp.keyId}
#
# Keep the PRIVATE key secret (treat like any signing key). Distribute the PUBLIC key to
# anyone who needs to verify checkpoint signatures.

# --- SIGNER (engine) ---
export OVERWATCH_CHECKPOINT_SIGNING_KEY=${b64(kp.privateKeyPem)}

# --- VERIFIER (auditor) ---
export OVERWATCH_CHECKPOINT_PUBLIC_KEY=${b64(kp.publicKeyPem)}

# --- raw PEMs (if you prefer files; point the env vars at the paths) ---
# private:
${kp.privateKeyPem.trim()}
# public:
${kp.publicKeyPem.trim()}`);
