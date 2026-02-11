import { defineConfig } from 'tsup';
import { resolve } from 'path';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    web: 'src/adapters/web.ts',
    taro: 'src/adapters/taro.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  minify: false,
  external: ['@tarojs/taro'],
  esbuildOptions(options) {
    options.alias = {
      '@': resolve(__dirname, 'src'),
      '@core': resolve(__dirname, 'src/core'),
      '@adapters': resolve(__dirname, 'src/adapters'),
      '@utils': resolve(__dirname, 'src/utils'),
    };
  },
});
