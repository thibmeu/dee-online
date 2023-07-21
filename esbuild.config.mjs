import * as esbuild from 'esbuild'
import path from 'node:path'
import fs from 'node:fs'

let wasmPlugin = {
  name: 'wasm',
  setup(build) {

    // Resolve ".wasm" files to a path with a namespace
    build.onResolve({ filter: /\.wasm$/ }, args => {
      if (args.resolveDir === '') {
        return // Ignore unresolvable paths
      }
      return {
        path: path.isAbsolute(args.path) ? args.path : path.join(args.resolveDir, args.path),
          namespace: 'wasm-binary',
      }
    })

    // Virtual modules in the "wasm-binary" namespace contain the
    // actual bytes of the WebAssembly file. This uses esbuild's
    // built-in "binary" loader instead of manually embedding the
    // binary data inside JavaScript code ourselves.
    build.onLoad({ filter: /.*/, namespace: 'wasm-binary' }, async (args) => ({
      contents: await fs.promises.readFile(args.path),
      loader: 'binary',
    }))
  },
}

await esbuild.build({
  entryPoints: ['service-worker/sw.js'],
  bundle: true,
  minify: false,
  format: 'esm',
  outfile: 'public/service-worker.js',
  plugins: [wasmPlugin],
})
