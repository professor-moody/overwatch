// ============================================================
// useLayout — ForceAtlas2 layout via graphology-layout-forceatlas2
// ============================================================

import { useRef, useCallback, useEffect } from 'react';
import type Graph from 'graphology';
import type Sigma from 'sigma';
import FA2Layout from 'graphology-layout-forceatlas2/worker';
import { LAYOUT_MAX_ITERATIONS } from '../lib/graph-constants';

export interface UseLayoutReturn {
  running: boolean;
  start: () => void;
  stop: () => void;
  toggle: () => void;
}

export function useLayout(graph: Graph, _rendererRef: React.MutableRefObject<Sigma | null>): UseLayoutReturn {
  const layoutRef = useRef<FA2Layout | null>(null);
  const runningRef = useRef(false);
  const iterRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stop = useCallback(() => {
    if (layoutRef.current) {
      layoutRef.current.stop();
      layoutRef.current.kill();
      layoutRef.current = null;
    }
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    runningRef.current = false;
    iterRef.current = 0;
  }, []);

  const start = useCallback(() => {
    if (runningRef.current) return;
    if (graph.order === 0) return;

    const layout = new FA2Layout(graph, {
      settings: {
        gravity: 1,
        scalingRatio: 10,
        barnesHutOptimize: graph.order > 100,
        barnesHutTheta: 0.5,
        strongGravityMode: false,
        slowDown: 5,
        adjustSizes: false,
      },
    });

    layoutRef.current = layout;
    runningRef.current = true;
    iterRef.current = 0;
    layout.start();

    // Auto-stop after max iterations
    timerRef.current = setInterval(() => {
      iterRef.current += 5; // ~5 iterations per frame at 60fps
      if (iterRef.current >= LAYOUT_MAX_ITERATIONS) {
        stop();
      }
    }, 16);
  }, [graph, stop]);

  const toggle = useCallback(() => {
    if (runningRef.current) stop();
    else start();
  }, [start, stop]);

  // Cleanup on unmount
  useEffect(() => {
    return () => { stop(); };
  }, [stop]);

  return {
    get running() { return runningRef.current; },
    start,
    stop,
    toggle,
  };
}
