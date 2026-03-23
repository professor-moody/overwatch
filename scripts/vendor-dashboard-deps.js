#!/usr/bin/env node
// ============================================================
// Vendor Dashboard Dependencies
// Copies browser-ready bundles into dist/dashboard/vendor/
// so the dashboard works without any external CDN access.
// ============================================================

import { mkdirSync, copyFileSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');
const vendorDir = resolve(root, 'dist', 'dashboard', 'vendor');
const require = createRequire(import.meta.url);

mkdirSync(vendorDir, { recursive: true });

function findFirst(candidates) {
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

// 1. graphology — ships a UMD browser bundle
const graphologyCandidates = [
  resolve(root, 'node_modules', 'graphology', 'dist', 'graphology.umd.min.js'),
  resolve(root, 'node_modules', 'graphology', 'dist', 'graphology.umd.js'),
];
const graphologyUmd = findFirst(graphologyCandidates);
if (!graphologyUmd) {
  console.error('[vendor] ERROR: Could not find graphology UMD bundle. Tried:', graphologyCandidates);
  process.exit(1);
}
copyFileSync(graphologyUmd, resolve(vendorDir, 'graphology.umd.min.js'));
console.log('[vendor] graphology.umd.min.js copied');

// 2. sigma — probe multiple known locations for the browser bundle
const sigmaRoot = resolve(root, 'node_modules', 'sigma');
if (!existsSync(sigmaRoot)) {
  console.error('[vendor] ERROR: sigma is not installed. Run "npm install" first.');
  process.exit(1);
}
const sigmaCandidates = [
  resolve(sigmaRoot, 'build', 'sigma.min.js'),
  resolve(sigmaRoot, 'build', 'sigma.js'),
  resolve(sigmaRoot, 'dist', 'sigma.min.js'),
  resolve(sigmaRoot, 'dist', 'sigma.js'),
  resolve(sigmaRoot, 'sigma.min.js'),
];
const sigmaBundle = findFirst(sigmaCandidates);
if (!sigmaBundle) {
  console.error('[vendor] ERROR: Could not find sigma browser bundle. Tried:', sigmaCandidates);
  console.error('[vendor] Ensure sigma is installed: npm install');
  process.exit(1);
}
copyFileSync(sigmaBundle, resolve(vendorDir, 'sigma.min.js'));
console.log(`[vendor] sigma.min.js copied from ${sigmaBundle}`);

// 3. graphology-layout-forceatlas2 — no UMD bundle; build a minimal IIFE wrapper
//    The dashboard only uses the synchronous `assign` export.
const fa2Pkg = resolve(root, 'node_modules', 'graphology-layout-forceatlas2');
const fa2Index = readFileSync(resolve(fa2Pkg, 'index.js'), 'utf8');
const fa2Helpers = readFileSync(resolve(fa2Pkg, 'helpers.js'), 'utf8');
const fa2Defaults = readFileSync(resolve(fa2Pkg, 'defaults.js'), 'utf8');
const fa2Iterate = readFileSync(resolve(fa2Pkg, 'iterate.js'), 'utf8');

// Build a self-contained IIFE that exposes window.graphologyLayoutForceAtlas2
const iife = `(function(global) {
  "use strict";

  // --- defaults.js ---
  var defaultsModule = {};
  (function(module, exports) {
    ${fa2Defaults.replace(/module\.exports\s*=/, 'module.exports =')}
  })(defaultsModule, {});
  var DEFAULT_SETTINGS = defaultsModule.exports || defaultsModule;

  // --- helpers.js ---
  var helpersModule = {};
  (function(module, exports) {
    ${fa2Helpers
      .replace(/var DEFAULT_SETTINGS = require.*?;/, '')
      .replace(/module\.exports\s*=/, 'module.exports =')}
  })(helpersModule, {});
  var helpers = helpersModule.exports || helpersModule;

  // --- iterate.js ---
  var iterateModule = {};
  (function(module, exports) {
    ${fa2Iterate
      .replace(/var DEFAULT_SETTINGS = require.*?;/, '')
      .replace(/module\.exports\s*=/, 'module.exports =')}
  })(iterateModule, {});
  var iterate = iterateModule.exports || iterateModule;

  // --- index.js (main) ---
  var indexModule = {};
  (function(module, exports) {
    var isGraph = function(g) { return g && typeof g.order === 'number' && typeof g.forEachNode === 'function'; };
    ${fa2Index
      .replace(/var isGraph = require.*?;/, '')
      .replace(/var iterate = require.*?;/, '')
      .replace(/var helpers = require.*?;/, '')
      .replace(/var DEFAULT_SETTINGS = require.*?;/, '')
      .replace(/module\.exports\s*=/, 'module.exports =')}
  })(indexModule, {});
  var fa2 = indexModule.exports || indexModule;

  global.graphologyLayoutForceAtlas2 = fa2;
})(typeof window !== 'undefined' ? window : typeof globalThis !== 'undefined' ? globalThis : this);
`;

writeFileSync(resolve(vendorDir, 'graphology-layout-forceatlas2.js'), iife);
console.log('[vendor] graphology-layout-forceatlas2.js built');

console.log('[vendor] All dashboard vendor dependencies ready.');
