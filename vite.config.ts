import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig } from 'vite';

export default defineConfig(() => {
  return {
    base: '/OpenShield/',
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(import.meta.dirname, '.'),
      },
    },
    build: {
      rolldownOptions: {
        output: {
          codeSplitting: {
            groups: [
              {
                name: 'react-vendor',
                test: /node_modules[\\/](react|react-dom|scheduler)/,
                priority: 30,
              },
              {
                name: 'charts-vendor',
                test: /node_modules[\\/](recharts|d3-|victory-vendor)/,
                priority: 25,
              },
              {
                name: 'i18n-vendor',
                test: /node_modules[\\/](i18next|react-i18next)/,
                priority: 20,
              },
              {
                name: 'icons-vendor',
                test: /node_modules[\\/]lucide-react/,
                priority: 15,
              },
              {
                name: 'motion-vendor',
                test: /node_modules[\\/](motion|framer-motion)/,
                priority: 15,
              },
            ],
          },
        },
      },
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
