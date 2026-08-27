import { create } from 'zustand';

interface DashboardUiStore {
  graphInspectorOpen: boolean;
  setGraphInspectorOpen: (open: boolean) => void;
  commandPaletteOpen: boolean;
  setCommandPaletteOpen: (open: boolean) => void;
  startWorkOpen: boolean;
  setStartWorkOpen: (open: boolean) => void;
}

export const useDashboardUiStore = create<DashboardUiStore>((set) => ({
  graphInspectorOpen: false,
  setGraphInspectorOpen: (open) => set({ graphInspectorOpen: open }),
  commandPaletteOpen: false,
  setCommandPaletteOpen: (open) => set({ commandPaletteOpen: open }),
  startWorkOpen: false,
  setStartWorkOpen: (open) => set({ startWorkOpen: open }),
}));
