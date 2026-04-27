import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Ported from old dashboard :root CSS variables
        background: '#080a0f',
        foreground: '#e2e0ea',
        surface: '#0e1118',
        elevated: '#161a24',
        hover: '#1c2030',
        active: '#232838',
        border: {
          subtle: 'rgba(255,255,255,0.05)',
          DEFAULT: 'rgba(255,255,255,0.08)',
          strong: 'rgba(255,255,255,0.14)',
        },
        muted: {
          DEFAULT: '#4e4d58',
          foreground: '#8a889a',
        },
        accent: {
          DEFAULT: '#5b8def',
          dim: 'rgba(91,141,239,0.12)',
          foreground: '#ffffff',
        },
        success: {
          DEFAULT: '#3ecf8e',
          dim: 'rgba(62,207,142,0.12)',
        },
        warning: {
          DEFAULT: '#eab308',
          dim: 'rgba(234,179,8,0.10)',
        },
        destructive: {
          DEFAULT: '#ef4444',
          dim: 'rgba(239,68,68,0.10)',
          foreground: '#ffffff',
        },
        purple: {
          DEFAULT: '#a78bfa',
          dim: 'rgba(167,139,250,0.10)',
        },
        pink: '#f472b6',
        // Node type colors
        node: {
          host: '#6e9eff',
          service: '#5dcaa5',
          credential: '#f0b54a',
          user: '#afa9ec',
          group: '#ed93b1',
          domain: '#97c459',
          objective: '#f07b6e',
          certificate: '#85b7eb',
          ca: '#79b9f2',
          'cert-template': '#c69bf7',
          webapp: '#4ecdc4',
          vulnerability: '#e05555',
          'cloud-identity': '#59b8e6',
          'cloud-resource': '#e6a459',
          'cloud-policy': '#a8d65c',
          'cloud-network': '#8fabb8',
        },
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['ui-monospace', 'SF Mono', 'Cascadia Code', 'Liberation Mono', 'Menlo', 'monospace'],
      },
      borderRadius: {
        sm: '4px',
        md: '8px',
        lg: '12px',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
};

export default config;
