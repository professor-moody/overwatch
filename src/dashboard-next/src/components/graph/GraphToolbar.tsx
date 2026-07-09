// ============================================================
// GraphToolbar — zoom, layout, export, layers, mode controls
// ============================================================

import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ChevronLeft,
  Download,
  HelpCircle,
  Layers,
  Maximize2,
  Minus,
  MoreHorizontal,
  Pause,
  Pencil,
  Play,
  Plus,
  RotateCcw,
  SlidersHorizontal,
  Undo2,
} from 'lucide-react';
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
  colorMode: string;
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
  onSetColorMode: (mode: string) => void;
  onSetFocusPreset: (preset: string) => void;
  onToggleLayer: (id: GraphLayerState['id']) => void;
  onToggleShortcuts: () => void;
  // Edit mode
  editMode?: boolean;
  onToggleEditMode?: () => void;
  onUndo?: () => void;
  undoCount?: number;
}

export interface LayoutToolbarState {
  layoutMode: GraphToolbarProps['layoutMode'];
  layoutRunning: boolean;
}

export interface LayoutToolbarAction {
  intent: 'pause' | 'resume';
  label: string;
  title: string;
  active: boolean;
}

export function getLayoutToolbarAction({ layoutMode, layoutRunning }: LayoutToolbarState): LayoutToolbarAction {
  if (layoutRunning) {
    return {
      intent: 'pause',
      label: 'Pause',
      title: 'Pause layout',
      active: true,
    };
  }

  return {
    intent: 'resume',
    label: layoutMode === 'manual' ? 'Resume auto' : 'Resume',
    title: layoutMode === 'manual' ? 'Resume auto layout' : 'Resume layout',
    active: false,
  };
}

export function GraphToolbar({
  nodeCount, edgeCount, layoutRunning, layoutMode, graphMode, labelDensity, colorMode, activeFocusPreset,
  layers,
  onZoomIn, onZoomOut, onFit, onToggleLayout, onResumeLayout, onReset, onResetPositions,
  onExportPNG, onExportSVG,
  onSetGraphMode, onSetLabelDensity, onSetColorMode, onSetFocusPreset,
  onToggleLayer,
  onToggleShortcuts,
  editMode, onToggleEditMode, onUndo, undoCount,
}: GraphToolbarProps) {
  const [showExport, setShowExport] = useState(false);
  const [showLayers, setShowLayers] = useState(false);
  const [showView, setShowView] = useState(false);
  const [showMore, setShowMore] = useState(false);
  const layoutAction = getLayoutToolbarAction({ layoutMode, layoutRunning });

  return (
    <div className="h-12 bg-surface border-b border-border flex items-center px-3 gap-2 text-xs flex-shrink-0 relative z-50 overflow-visible">
      {/* Back to the Operator Console (the operator's home) */}
      <Link to="/agents" className="text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 min-w-0">
        <ChevronLeft size={14} />
        <span className="hidden sm:inline">Console</span>
      </Link>

      <span className="text-accent font-semibold whitespace-nowrap">◆ OVERWATCH</span>
      <span className="font-medium text-muted-foreground whitespace-nowrap hidden md:inline">Graph</span>

      <div className="flex-1" />

      {/* Graph Controls */}
      <div className="flex items-center gap-1 min-w-0">
        <ToolBtn onClick={onZoomIn} title="Zoom in"><Plus size={14} /></ToolBtn>
        <ToolBtn onClick={onZoomOut} title="Zoom out"><Minus size={14} /></ToolBtn>
        <ToolBtn onClick={onFit} title="Fit to screen"><Maximize2 size={14} /><span className="sr-only">Fit</span></ToolBtn>
        <Sep />
        <LayoutStatus mode={layoutMode} running={layoutRunning} />
        <ToolBtn
          onClick={layoutAction.intent === 'pause' ? onToggleLayout : onResumeLayout}
          title={layoutAction.title}
          active={layoutAction.active}
        >
          {layoutAction.intent === 'pause' ? <Pause size={14} /> : <Play size={14} />}
          <span className="hidden lg:inline">{layoutAction.label}</span>
        </ToolBtn>
        <ToolBtn onClick={onReset} title="Clear graph focus and filters">Clear view</ToolBtn>
        <Sep />

        <div className="relative">
          <ToolBtn onClick={() => { setShowView(!showView); setShowExport(false); setShowLayers(false); setShowMore(false); }} title="View controls">
            <SlidersHorizontal size={14} />
            <span className="hidden lg:inline">View</span>
          </ToolBtn>
          {showView && (
            <Dropdown onClose={() => setShowView(false)} wide>
              <div className="space-y-2 p-2">
                <SelectGroup label="Mode" value={graphMode} onChange={onSetGraphMode} options={['overview', 'focused', 'raw']} />
                <SelectGroup label="Labels" value={labelDensity} onChange={onSetLabelDensity} options={['minimal', 'balanced', 'verbose']} />
                <SelectGroup
                  label="Color by"
                  value={colorMode}
                  onChange={onSetColorMode}
                  options={['type', 'community', 'tier']}
                  optionLabels={['Type', 'Community', 'Tier']}
                />
                <SelectGroup
                  label="Focus"
                  value={activeFocusPreset || ''}
                  onChange={onSetFocusPreset}
                  options={['', ...Object.keys(FOCUS_PRESETS)]}
                  optionLabels={['None', ...Object.keys(FOCUS_PRESETS)]}
                />
              </div>
            </Dropdown>
          )}
        </div>

        {/* Export dropdown */}
        <div className="relative">
          <ToolBtn onClick={() => { setShowExport(!showExport); setShowLayers(false); setShowView(false); setShowMore(false); }} title="Export">
            <Download size={14} />
            <span className="hidden lg:inline">Export</span>
          </ToolBtn>
          {showExport && (
            <Dropdown onClose={() => setShowExport(false)}>
              <DropBtn onClick={() => { onExportPNG(); setShowExport(false); }}>Export PNG</DropBtn>
              <DropBtn onClick={() => { onExportSVG(); setShowExport(false); }}>Export SVG</DropBtn>
            </Dropdown>
          )}
        </div>

        {/* Layers dropdown */}
        <div className="relative">
          <ToolBtn onClick={() => { setShowLayers(!showLayers); setShowExport(false); setShowView(false); setShowMore(false); }} title="Layers">
            <Layers size={14} />
            <span className="hidden lg:inline">Layers</span>
          </ToolBtn>
          {showLayers && (
            <Dropdown onClose={() => setShowLayers(false)} wide>
              {layers.map(layer => (
                <LayerBtn key={layer.id} layer={layer} onToggle={() => onToggleLayer(layer.id)} />
              ))}
            </Dropdown>
          )}
        </div>

        {onToggleEditMode && (
          <>
            <Sep />
            <ToolBtn onClick={onToggleEditMode} title="Toggle edit mode" active={editMode}><Pencil size={14} /><span className="hidden lg:inline">Edit</span></ToolBtn>
            {editMode && onUndo && (undoCount ?? 0) > 0 && (
              <ToolBtn onClick={onUndo} title="Undo last edit"><Undo2 size={14} /><span className="hidden xl:inline">Undo {undoCount}</span></ToolBtn>
            )}
          </>
        )}

      <Sep />

      {/* Stats */}
      <div className="hidden sm:flex items-center gap-3 text-muted-foreground">
        <Stat label="Nodes" value={nodeCount} />
        <Stat label="Edges" value={edgeCount} />
      </div>

        <div className="relative">
          <ToolBtn onClick={() => { setShowMore(!showMore); setShowExport(false); setShowLayers(false); setShowView(false); }} title="More graph controls">
            <MoreHorizontal size={14} />
          </ToolBtn>
          {showMore && (
            <Dropdown onClose={() => setShowMore(false)}>
              <DropBtn onClick={() => { onResetPositions(); setShowMore(false); }}><RotateCcw size={13} /> Reset positions</DropBtn>
              <DropBtn onClick={() => { onToggleShortcuts(); setShowMore(false); }}><HelpCircle size={13} /> Shortcuts</DropBtn>
            </Dropdown>
          )}
        </div>
      </div>
    </div>
  );
}

export function createToolbarActionHandler(action: () => void): (_event?: unknown) => void {
  return () => action();
}

function ToolBtn({ children, onClick, title, active }: {
  children: React.ReactNode; onClick: () => void; title?: string; active?: boolean;
}) {
  return (
    <button
      onClick={createToolbarActionHandler(onClick)}
      title={title}
      className={cn(
        'inline-flex h-7 items-center justify-center gap-1 px-2 py-1 rounded text-xs transition-colors whitespace-nowrap',
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
      className="w-full px-3 py-1.5 text-left text-xs hover:bg-hover transition-colors flex items-center gap-2"
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
    <label className="flex items-center justify-between gap-2 text-muted-foreground">
      <span className="text-[10px] min-w-10">{label}</span>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="text-[11px] bg-elevated border border-border rounded px-1 py-0.5 text-foreground min-w-28"
      >
        {options.map((opt, i) => (
          <option key={opt} value={opt}>{optionLabels?.[i] || opt}</option>
        ))}
      </select>
    </label>
  );
}
