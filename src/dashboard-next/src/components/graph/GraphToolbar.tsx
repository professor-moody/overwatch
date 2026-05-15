// ============================================================
// GraphToolbar — zoom, layout, export, layers, mode controls
// ============================================================

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { FOCUS_PRESETS } from '../../lib/graph-constants';
import { cn } from '../../lib/utils';
import type { GraphLayerState } from '../../lib/graph-layers';

interface GraphToolbarProps {
  nodeCount: number;
  edgeCount: number;
  layoutRunning: boolean;
  layoutMode: 'auto' | 'manual' | 'paused';
  graphMode: string;
  labelDensity: string;
  activeFocusPreset: string | null;
  layers: GraphLayerState[];
  // Actions
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFit: () => void;
  onToggleLayout: () => void;
  onResumeLayout: () => void;
  onReset: () => void;
  onResetPositions: () => void;
  onExportPNG: () => void;
  onExportSVG: () => void;
  onSetGraphMode: (mode: string) => void;
  onSetLabelDensity: (density: string) => void;
  onSetFocusPreset: (preset: string) => void;
  onToggleLayer: (id: GraphLayerState['id']) => void;
  onToggleShortcuts: () => void;
  // Edit mode
  editMode?: boolean;
  onToggleEditMode?: () => void;
  onUndo?: () => void;
  undoCount?: number;
}

export function GraphToolbar({
  nodeCount, edgeCount, layoutRunning, layoutMode, graphMode, labelDensity, activeFocusPreset,
  layers,
  onZoomIn, onZoomOut, onFit, onToggleLayout, onResumeLayout, onReset, onResetPositions,
  onExportPNG, onExportSVG,
  onSetGraphMode, onSetLabelDensity, onSetFocusPreset,
  onToggleLayer,
  onToggleShortcuts,
  editMode, onToggleEditMode, onUndo, undoCount,
}: GraphToolbarProps) {
  const [showExport, setShowExport] = useState(false);
  const [showLayers, setShowLayers] = useState(false);

  return (
    <div className="h-12 bg-surface border-b border-border flex items-center px-3 gap-2 text-xs flex-shrink-0 relative z-50 overflow-x-auto overflow-y-visible">
      {/* Back */}
      <Link to="/overview" className="text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M9 2L4 7l5 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
        Dashboard
      </Link>

      <span className="text-accent font-semibold">◆ OVERWATCH</span>
      <span className="font-medium">Graph Explorer</span>

      <div className="flex-1" />

      {/* Graph Controls */}
      <div className="flex items-center gap-1">
        <ToolBtn onClick={onZoomIn} title="Zoom in">+</ToolBtn>
        <ToolBtn onClick={onZoomOut} title="Zoom out">−</ToolBtn>
        <ToolBtn onClick={onFit} title="Fit to screen">Fit</ToolBtn>
        <Sep />
        <LayoutStatus mode={layoutMode} running={layoutRunning} />
        {layoutMode !== 'auto' && <ToolBtn onClick={onResumeLayout} title="Resume auto layout">Resume</ToolBtn>}
        <ToolBtn onClick={onToggleLayout} title="Pause or resume layout" active={layoutRunning}>Layout</ToolBtn>
        <ToolBtn onClick={onReset} title="Reset filters and focus">Reset</ToolBtn>
        <ToolBtn onClick={onResetPositions} title="Clear saved positions and relayout">Reset positions</ToolBtn>
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
              {layers.map(layer => (
                <LayerBtn key={layer.id} layer={layer} onToggle={() => onToggleLayer(layer.id)} />
              ))}
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
        'px-2 py-1 rounded text-xs transition-colors whitespace-nowrap',
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

function LayoutStatus({ mode, running }: { mode: GraphToolbarProps['layoutMode']; running: boolean }) {
  const label = mode === 'manual' ? 'Manual layout' : mode === 'paused' ? 'Paused' : 'Auto layout';
  return (
    <span className={cn(
      'px-2 py-1 rounded text-[11px] border whitespace-nowrap',
      mode === 'manual' && 'bg-warning/10 text-warning border-warning/20',
      mode === 'paused' && 'bg-elevated text-muted-foreground border-border',
      mode === 'auto' && 'bg-success/10 text-success border-success/20',
    )}>
      {label}{running && mode === 'auto' ? ' · running' : ''}
    </span>
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

function LayerBtn({ layer, onToggle }: { layer: GraphLayerState; onToggle: () => void }) {
  return (
    <button
      onClick={layer.available ? onToggle : undefined}
      disabled={!layer.available}
      title={layer.available ? layer.description : layer.disabledReason}
      className={cn(
        'w-full px-3 py-1.5 text-left text-xs transition-colors flex items-start gap-2',
        layer.available ? 'hover:bg-hover' : 'opacity-45 cursor-not-allowed',
        layer.enabled && 'text-accent',
      )}
    >
      <span className={cn(
        'mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0',
        layer.enabled ? 'bg-accent' : 'bg-muted',
      )} />
      <span className="min-w-0">
        <span className="block text-foreground">{layer.label}</span>
        <span className="block text-[10px] text-muted-foreground leading-snug">
          {layer.available ? layer.description : layer.disabledReason}
        </span>
      </span>
    </button>
  );
}

function DropBtn({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full px-3 py-1.5 text-left text-xs hover:bg-hover transition-colors"
    >
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
