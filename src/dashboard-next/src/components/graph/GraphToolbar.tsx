// ============================================================
// GraphToolbar — zoom, layout, export, layers, mode controls
// ============================================================

import { useState } from 'react';
import { FOCUS_PRESETS } from '../../lib/graph-constants';
import { cn } from '../../lib/utils';

interface GraphToolbarProps {
  nodeCount: number;
  edgeCount: number;
  layoutRunning: boolean;
  graphMode: string;
  labelDensity: string;
  activeFocusPreset: string | null;
  // Overlay toggles
  attackPathActive: boolean;
  credFlowActive: boolean;
  communityHullsActive: boolean;
  showEdgeLabels: boolean;
  hideOrphans: boolean;
  hideReachableOnly: boolean;
  // Actions
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFit: () => void;
  onToggleLayout: () => void;
  onReset: () => void;
  onExportPNG: () => void;
  onExportSVG: () => void;
  onSetGraphMode: (mode: string) => void;
  onSetLabelDensity: (density: string) => void;
  onSetFocusPreset: (preset: string) => void;
  onToggleAttackPath: () => void;
  onToggleCredFlow: () => void;
  onToggleCommunityHulls: () => void;
  onToggleEdgeLabels: () => void;
  onToggleHideOrphans: () => void;
  onToggleHideReachableOnly: () => void;
  onToggleShortcuts: () => void;
  // Edit mode
  editMode?: boolean;
  onToggleEditMode?: () => void;
  onUndo?: () => void;
  undoCount?: number;
}

export function GraphToolbar({
  nodeCount, edgeCount, layoutRunning, graphMode, labelDensity, activeFocusPreset,
  attackPathActive, credFlowActive, communityHullsActive, showEdgeLabels, hideOrphans, hideReachableOnly,
  onZoomIn, onZoomOut, onFit, onToggleLayout, onReset,
  onExportPNG, onExportSVG,
  onSetGraphMode, onSetLabelDensity, onSetFocusPreset,
  onToggleAttackPath, onToggleCredFlow, onToggleCommunityHulls, onToggleEdgeLabels,
  onToggleHideOrphans, onToggleHideReachableOnly,
  onToggleShortcuts,
  editMode, onToggleEditMode, onUndo, undoCount,
}: GraphToolbarProps) {
  const [showExport, setShowExport] = useState(false);
  const [showLayers, setShowLayers] = useState(false);

  return (
    <div className="h-12 bg-surface border-b border-border flex items-center px-3 gap-2 text-xs flex-shrink-0 relative z-50">
      {/* Back */}
      <a href="/" className="text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M9 2L4 7l5 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
        Dashboard
      </a>

      <span className="text-accent font-semibold">◆ OVERWATCH</span>
      <span className="font-medium">Graph Explorer</span>

      <div className="flex-1" />

      {/* Graph Controls */}
      <div className="flex items-center gap-1">
        <ToolBtn onClick={onZoomIn} title="Zoom in">+</ToolBtn>
        <ToolBtn onClick={onZoomOut} title="Zoom out">−</ToolBtn>
        <ToolBtn onClick={onFit} title="Fit to screen">Fit</ToolBtn>
        <Sep />
        <ToolBtn onClick={onToggleLayout} title="Toggle layout" active={layoutRunning}>Layout</ToolBtn>
        <ToolBtn onClick={onReset} title="Reset filters">Reset</ToolBtn>
        <Sep />

        {/* Export dropdown */}
        <div className="relative">
          <ToolBtn onClick={() => { setShowExport(!showExport); setShowLayers(false); }} title="Export">Export ▾</ToolBtn>
          {showExport && (
            <Dropdown onClose={() => setShowExport(false)}>
              <DropBtn onClick={() => { onExportPNG(); setShowExport(false); }}>Export PNG</DropBtn>
              <DropBtn onClick={() => { onExportSVG(); setShowExport(false); }}>Export SVG</DropBtn>
            </Dropdown>
          )}
        </div>

        {/* Layers dropdown */}
        <div className="relative">
          <ToolBtn onClick={() => { setShowLayers(!showLayers); setShowExport(false); }} title="Layers">Layers ▾</ToolBtn>
          {showLayers && (
            <Dropdown onClose={() => setShowLayers(false)} wide>
              <DropBtn onClick={onToggleAttackPath} active={attackPathActive}>Attack Path</DropBtn>
              <DropBtn onClick={onToggleCredFlow} active={credFlowActive}>Credential Flow</DropBtn>
              <DropBtn onClick={onToggleCommunityHulls} active={communityHullsActive}>Community Hulls</DropBtn>
              <DropBtn onClick={onToggleEdgeLabels} active={showEdgeLabels}>Edge Labels</DropBtn>
              <DropBtn onClick={onToggleHideOrphans} active={hideOrphans}>Hide Orphans</DropBtn>
              <DropBtn onClick={onToggleHideReachableOnly} active={hideReachableOnly}>Hide Reachable-Only</DropBtn>
            </Dropdown>
          )}
        </div>

        <ToolBtn onClick={onToggleShortcuts} title="Keyboard shortcuts">?</ToolBtn>
        {onToggleEditMode && (
          <>
            <Sep />
            <ToolBtn onClick={onToggleEditMode} title="Toggle edit mode" active={editMode}>Edit</ToolBtn>
            {editMode && onUndo && (undoCount ?? 0) > 0 && (
              <ToolBtn onClick={onUndo} title="Undo last edit">Undo ({undoCount})</ToolBtn>
            )}
          </>
        )}
      </div>

      <Sep />

      {/* View controls */}
      <div className="flex items-center gap-2">
        <SelectGroup label="Mode" value={graphMode} onChange={onSetGraphMode} options={['overview', 'focused', 'raw']} />
        <SelectGroup label="Labels" value={labelDensity} onChange={onSetLabelDensity} options={['minimal', 'balanced', 'verbose']} />
        <SelectGroup
          label="Focus"
          value={activeFocusPreset || ''}
          onChange={onSetFocusPreset}
          options={['', ...Object.keys(FOCUS_PRESETS)]}
          optionLabels={['None', ...Object.keys(FOCUS_PRESETS)]}
        />
      </div>

      <Sep />

      {/* Stats */}
      <div className="flex items-center gap-3 text-muted-foreground">
        <Stat label="Nodes" value={nodeCount} />
        <Stat label="Edges" value={edgeCount} />
      </div>
    </div>
  );
}

function ToolBtn({ children, onClick, title, active }: {
  children: React.ReactNode; onClick: () => void; title?: string; active?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      className={cn(
        'px-2 py-1 rounded text-xs transition-colors',
        active ? 'bg-accent/20 text-accent' : 'text-muted-foreground hover:text-foreground hover:bg-hover',
      )}
    >
      {children}
    </button>
  );
}

function Sep() {
  return <div className="w-px h-5 bg-border mx-0.5" />;
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="text-center">
      <div className="text-accent font-mono text-xs">{value}</div>
      <div className="text-[9px]">{label}</div>
    </div>
  );
}

function Dropdown({ children, onClose, wide }: { children: React.ReactNode; onClose: () => void; wide?: boolean }) {
  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} />
      <div className={cn(
        'absolute right-0 top-full mt-1 bg-surface border border-border rounded-md shadow-xl z-50 py-1',
        wide ? 'min-w-48' : 'min-w-32',
      )}>
        {children}
      </div>
    </>
  );
}

function DropBtn({ children, onClick, active }: { children: React.ReactNode; onClick: () => void; active?: boolean }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full px-3 py-1.5 text-left text-xs hover:bg-hover transition-colors flex items-center gap-2',
        active && 'text-accent',
      )}
    >
      {active && <span className="w-1.5 h-1.5 rounded-full bg-accent" />}
      {children}
    </button>
  );
}

function SelectGroup({ label, value, onChange, options, optionLabels }: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
  optionLabels?: string[];
}) {
  return (
    <label className="flex items-center gap-1 text-muted-foreground">
      <span className="text-[10px]">{label}</span>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="text-[11px] bg-elevated border border-border rounded px-1 py-0.5 text-foreground"
      >
        {options.map((opt, i) => (
          <option key={opt} value={opt}>{optionLabels?.[i] || opt}</option>
        ))}
      </select>
    </label>
  );
}
