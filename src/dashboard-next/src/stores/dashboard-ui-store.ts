import { create } from 'zustand';

interface DashboardUiStore {
  graphInspectorOpen: boolean;
  setGraphInspectorOpen: (open: boolean) => void;
}

export const useDashboardUiStore = create<DashboardUiStore>((set) => ({
  graphInspectorOpen: false,
  setGraphInspectorOpen: (open) => set({ graphInspectorOpen: open }),
}));
