// ============================================================
// GraphContainer — sigma.js mount point + resize observer
// ============================================================

import { useRef, useEffect } from 'react';
import type Sigma from 'sigma';

interface GraphContainerProps {
  onMount: (container: HTMLElement) => void;
  rendererRef: React.MutableRefObject<Sigma | null>;
}

export function GraphContainer({ onMount, rendererRef }: GraphContainerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mountedRef = useRef(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || mountedRef.current) return;
    mountedRef.current = true;
    onMount(el);
  }, [onMount]);

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
      ref={containerRef}
      className="absolute inset-0"
      style={{ background: '#080a0f' }}
    />
  );
}
