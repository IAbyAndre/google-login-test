const { defineConfig } = require('vite');
const path = require('node:path');
module.exports = defineConfig({
  root: 'public', publicDir: false,
  build: {
    outDir: '../dist', emptyOutDir: true,
    rollupOptions: {
      input: {
        index: path.resolve(__dirname, 'public/index.html'),
        dashboard: path.resolve(__dirname, 'public/dashboard.html'),
      },
    },
  },
  server: {
    host: '0.0.0.0', port: 8000, strictPort: true,
    allowedHosts: ['lion-ruby.exe.xyz'],
    proxy: { '/api': 'http://127.0.0.1:3001', '/dashboard': 'http://127.0.0.1:3001' },
  },
});
