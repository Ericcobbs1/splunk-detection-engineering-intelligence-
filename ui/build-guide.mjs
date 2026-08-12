import { build } from 'esbuild';

await build({
  entryPoints: ['ui/interactive-guide.jsx'],
  bundle: true,
  minify: true,
  format: 'iife',
  target: ['es2020'],
  define: {'process.env.NODE_ENV': '"production"'},
  outfile: 'app/appserver/static/dei_interactive_guide_v2.js',
  legalComments: 'none',
});

await build({
  entryPoints: ['ui/home-globe.jsx'],
  bundle: true,
  minify: true,
  format: 'iife',
  target: ['es2020'],
  define: {'process.env.NODE_ENV': '"production"'},
  outfile: 'app/appserver/static/dei_home_globe_react_v1.js',
  legalComments: 'none',
});
