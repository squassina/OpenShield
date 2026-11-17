import { useCallback, useSyncExternalStore } from 'react';

export type ThemeMode = 'light' | 'dark';

export const THEME_STORAGE_KEY = 'openshield-theme';

const listeners = new Set<() => void>();

function readStoredTheme(): ThemeMode {
  if (typeof window === 'undefined') return 'dark';
  try {
    const raw = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (raw === 'light' || raw === 'dark') return raw;
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      return 'light';
    }
  } catch {
    // Ignore storage access failures in restricted contexts
  }
  return 'dark';
}

let currentTheme: ThemeMode = readStoredTheme();

export function applyThemeClass(theme: ThemeMode): void {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  if (theme === 'dark') {
    root.classList.add('dark');
    root.style.colorScheme = 'dark';
  } else {
    root.classList.remove('dark');
    root.style.colorScheme = 'light';
  }
}

// Synchronize initial DOM state on module load
applyThemeClass(currentTheme);

export function getTheme(): ThemeMode {
  return currentTheme;
}

export function setTheme(next: ThemeMode): void {
  if (next === currentTheme) return;
  currentTheme = next;
  applyThemeClass(next);
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, next);
  } catch {
    // Ignore storage quota / privacy failures
  }
  listeners.forEach((listener) => listener());
}

export function toggleTheme(): ThemeMode {
  const next: ThemeMode = currentTheme === 'dark' ? 'light' : 'dark';
  setTheme(next);
  return next;
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  if (typeof window === 'undefined') {
    return () => {
      listeners.delete(listener);
    };
  }
  const handleStorage = (event: StorageEvent) => {
    if (event.key === THEME_STORAGE_KEY && (event.newValue === 'light' || event.newValue === 'dark')) {
      currentTheme = event.newValue;
      applyThemeClass(currentTheme);
      listeners.forEach((fn) => fn());
    }
  };
  window.addEventListener('storage', handleStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener('storage', handleStorage);
  };
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getTheme, () => 'dark' as ThemeMode);
  const toggle = useCallback(() => toggleTheme(), []);
  const updateTheme = useCallback((next: ThemeMode) => setTheme(next), []);
  return {
    theme,
    isDark: theme === 'dark',
    setTheme: updateTheme,
    toggleTheme: toggle,
  };
}
