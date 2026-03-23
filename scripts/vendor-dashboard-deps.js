#!/usr/bin/env node
// ============================================================
// Vendor Dashboard Dependencies
// Copies browser-ready bundles into dist/dashboard/vendor/
// so the dashboard works without any external CDN access.
// ============================================================

import { mkdirSync, copyFileSync, writeFileSync, readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');
const vendorDir = resolve(root, 'dist', 'dashboard', 'vendor');
const require = createRequire(import.meta.url);

mkdirSync(vendorDir, { recursive: true });

// 1. graphology — ships a UMD browser bundle
const graphologyUmd = resolve(root, 'node_modules', 'graphology', 'dist', 'graphology.umd.min.js');
copyFileSync(graphologyUmd, resolve(vendorDir, 'graphology.umd.min.js'));
console.log('[vendor] graphology.umd.min.js copied');

// 2. sigma — ships a pre-built browser bundle
const sigmaBuild = resolve(root, 'node_modules', 'sigma', 'build', 'sigma.min.js');
copyFileSync(sigmaBuild, resolve(vendorDir, 'sigma.min.js'));
console.log('[vendor] sigma.min.js copied');

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
