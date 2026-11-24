import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { cpSync } from 'node:fs';

// 单文件产物改名叫 index2.html 落 daemon/public，和老 index.html 并行验证。
export default defineConfig({
  plugins: [
    vue(),
    viteSingleFile(),
    {
      name: 'emit-index2',
      closeBundle() {
        cpSync('dist/index.html', '../daemon/public/index2.html');
      },
    },
  ],
  build: { outDir: 'dist' },
});
