// ============================================================
// GraphContainer — sigma.js mount point + resize observer
// ============================================================

import { useRef, useEffect, useCallback } from 'react';
import type Sigma from 'sigma';

interface GraphContainerProps {
  onMount: (container: HTMLElement) => void;
  rendererRef: React.MutableRefObject<Sigma | null>;
}

export function GraphContainer({ onMount, rendererRef }: GraphContainerProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  const setContainerRef = useCallback((el: HTMLDivElement | null) => {
    containerRef.current = el;
    if (el && !rendererRef.current) onMount(el);
  }, [onMount, rendererRef]);

  // ResizeObserver for responsive sigma
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const ro = new ResizeObserver(() => {
      rendererRef.current?.refresh();
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [rendererRef]);

  return (
    <div
      ref={setContainerRef}
      className="absolute inset-0"
      style={{ background: '#080a0f' }}
    />
  );
}
