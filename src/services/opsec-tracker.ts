// ============================================================
// Overwatch — Adaptive OPSEC Tracker
// Tracks cumulative noise budget per host, domain, and globally.
// Detects defensive response signals and recommends approach
// based on remaining noise budget.
// ============================================================

import type { EngineContext } from './engine-context.js';

// --- Types ---

export interface DefensiveSignal {
  type: 'lockout' | 'connection_reset' | 'honeypot' | 'rate_limit' | 'block';
  host_id?: string;
  domain?: string;
  detected_at: string;
  description: string;
}

export interface OpsecContext {
  noise_budget_remaining: number;
  global_noise_spent: number;
  host_noise_spent?: number;
  domain_noise_spent?: number;
  recommended_approach: 'quiet' | 'normal' | 'loud';
  time_window_remaining_hours?: number;
  defensive_signals: DefensiveSignal[];
  warning?: string;
}

export interface OpsecTrackerState {
  noise_by_host: Record<string, number>;
  noise_by_domain: Record<string, number>;
  global_noise: number;
  defensive_signals: DefensiveSignal[];
}

export interface RecordNoiseOpts {
  action_id?: string;
  host_id?: string;
  domain?: string;
  noise_estimate: number;
  noise_actual?: number;
}

// --- Constants ---

/** Defensive signals older than this are excluded from context (24 hours). */
const SIGNAL_STALENESS_MS = 24 * 60 * 60 * 1000;

// --- Service ---

export class OpsecTracker {
  private ctx: EngineContext;
  private noiseByHost: Map<string, number> = new Map();
  private noiseByDomain: Map<string, number> = new Map();
  private globalNoise: number = 0;
  private defensiveSignals: DefensiveSignal[] = [];

  constructor(ctx: EngineContext) {
    this.ctx = ctx;
  }

  // ---- Noise recording ----

  recordNoise(opts: RecordNoiseOpts): void {
    const noise = opts.noise_actual ?? opts.noise_estimate;
    if (noise <= 0) return;

    this.globalNoise += noise;

    if (opts.host_id) {
      const prev = this.noiseByHost.get(opts.host_id) ?? 0;
      this.noiseByHost.set(opts.host_id, prev + noise);
    }
    if (opts.domain) {
      const prev = this.noiseByDomain.get(opts.domain) ?? 0;
      this.noiseByDomain.set(opts.domain, prev + noise);
    }
  }

  // ---- Defensive signals ----

  recordDefensiveSignal(signal: DefensiveSignal): void {
    this.defensiveSignals.push(signal);
  }

  private getRecentSignals(host_id?: string, domain?: string): DefensiveSignal[] {
    const cutoff = Date.now() - SIGNAL_STALENESS_MS;
    return this.defensiveSignals.filter(s => {
      if (new Date(s.detected_at).getTime() < cutoff) return false;
      if (host_id && s.host_id && s.host_id !== host_id) return false;
      if (domain && s.domain && s.domain !== domain) return false;
      return true;
    });
  }

  // ---- Context for validate_action ----

  getNoiseContext(opts?: { host_id?: string; domain?: string }): OpsecContext {
    const maxNoise = this.ctx.config.opsec.max_noise;
    const remaining = Math.max(0, maxNoise - this.globalNoise);
    const ratio = maxNoise > 0 ? remaining / maxNoise : 0;

    const context: OpsecContext = {
      noise_budget_remaining: round4(remaining),
      global_noise_spent: round4(this.globalNoise),
      recommended_approach: this.recommendApproach(ratio),
      defensive_signals: this.getRecentSignals(opts?.host_id, opts?.domain),
    };

    if (opts?.host_id) {
      context.host_noise_spent = round4(this.noiseByHost.get(opts.host_id) ?? 0);
    }
    if (opts?.domain) {
      context.domain_noise_spent = round4(this.noiseByDomain.get(opts.domain) ?? 0);
    }

    const timeRemaining = this.getTimeWindowRemainingHours();
    if (timeRemaining !== undefined) {
      context.time_window_remaining_hours = timeRemaining;
    }

    // Warnings
    if (remaining <= 0) {
      context.warning = 'Noise budget exhausted — only passive/zero-noise actions recommended.';
    } else if (ratio < 0.15) {
      context.warning = 'Noise budget critically low — switch to quiet techniques only.';
    } else if (context.defensive_signals.length > 0) {
      context.warning = `${context.defensive_signals.length} defensive signal(s) detected — proceed with caution.`;
    }

    return context;
  }

  private recommendApproach(budgetRatio: number): 'quiet' | 'normal' | 'loud' {
    // Defensive signals force quiet regardless of budget
    const recentSignals = this.getRecentSignals();
    if (recentSignals.length >= 3) return 'quiet';

    if (budgetRatio > 0.6) return 'loud';
    if (budgetRatio > 0.3) return 'normal';
    return 'quiet';
  }

  // ---- Time window ----

  private getTimeWindowRemainingHours(): number | undefined {
    const tw = this.ctx.config.opsec.time_window;
    if (!tw) return undefined;

    const now = new Date();
    const hour = now.getHours() + now.getMinutes() / 60;
    const { start_hour, end_hour } = tw;

    // Check if currently in window
    const inWindow = start_hour <= end_hour
      ? hour >= start_hour && hour < end_hour
      : hour >= start_hour || hour < end_hour;

    if (!inWindow) return 0;

    // Calculate hours remaining in window
    if (start_hour <= end_hour) {
      return round4(end_hour - hour);
    }
    // Wrap-around: e.g. 22:00-06:00
    if (hour >= start_hour) {
      return round4((24 - hour) + end_hour);
    }
    return round4(end_hour - hour);
  }

  // ---- Ceiling checks ----

  isApproachingCeiling(host_id?: string, domain?: string): boolean {
    const maxNoise = this.ctx.config.opsec.max_noise;
    if (maxNoise <= 0) return true;

    // Global check
    if (this.globalNoise / maxNoise >= 0.85) return true;

    // Per-host check: if any single host has consumed >50% of the global budget,
    // it's generating disproportionate noise
    if (host_id) {
      const hostNoise = this.noiseByHost.get(host_id) ?? 0;
      if (hostNoise / maxNoise >= 0.5) return true;
    }

    if (domain) {
      const domainNoise = this.noiseByDomain.get(domain) ?? 0;
      if (domainNoise / maxNoise >= 0.5) return true;
    }

    return false;
  }

  // ---- Getters ----

  getGlobalNoise(): number { return this.globalNoise; }
  getHostNoise(host_id: string): number { return this.noiseByHost.get(host_id) ?? 0; }
  getDomainNoise(domain: string): number { return this.noiseByDomain.get(domain) ?? 0; }
  getAllDefensiveSignals(): DefensiveSignal[] { return [...this.defensiveSignals]; }

  // ---- Serialization ----

  serialize(): OpsecTrackerState {
    return {
      noise_by_host: Object.fromEntries(this.noiseByHost),
      noise_by_domain: Object.fromEntries(this.noiseByDomain),
      global_noise: this.globalNoise,
      defensive_signals: this.defensiveSignals,
    };
  }

  static deserialize(state: OpsecTrackerState, ctx: EngineContext): OpsecTracker {
    const tracker = new OpsecTracker(ctx);
    tracker.noiseByHost = new Map(Object.entries(state.noise_by_host || {}));
    tracker.noiseByDomain = new Map(Object.entries(state.noise_by_domain || {}));
    tracker.globalNoise = state.global_noise || 0;
    tracker.defensiveSignals = state.defensive_signals || [];
    return tracker;
  }
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}
