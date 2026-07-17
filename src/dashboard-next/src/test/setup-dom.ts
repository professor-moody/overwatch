import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';
import { resetBrowserStorageMemoryForTest } from '../lib/browser-storage';
import { resetDashboardAuthMemoryForTest } from '../lib/dashboard-transport';

afterEach(() => {
  cleanup();
  resetBrowserStorageMemoryForTest();
  resetDashboardAuthMemoryForTest();
  vi.restoreAllMocks();
});

Object.defineProperty(window, 'matchMedia', {
  configurable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

class ObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

Object.defineProperty(globalThis, 'ResizeObserver', { configurable: true, value: ObserverStub });
Object.defineProperty(globalThis, 'IntersectionObserver', { configurable: true, value: ObserverStub });
Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
  configurable: true,
  value: vi.fn(),
});

if (!URL.createObjectURL) URL.createObjectURL = vi.fn(() => 'blob:dashboard-test');
if (!URL.revokeObjectURL) URL.revokeObjectURL = vi.fn();
