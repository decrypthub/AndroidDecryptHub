import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { cpSync } from 'node:fs';

export default defineConfig({
  plugins: [
    vue(),
    viteSingleFile(),
    {
      name: 'emit-index',
      writeBundle() {
        cpSync('dist/index.html', '../daemon/public/index.html');
      },
    },
  ],
  build: { outDir: 'dist' },
});
