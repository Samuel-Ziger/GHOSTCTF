import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const p = path.join(root, 'server', 'index.js');
let s = fs.readFileSync(p, 'utf8');
const start = s.indexOf('async function runPipeline(ctx)');
const end = s.indexOf("app.post('/api/recon/stream'");
if (start < 0 || end < 0) throw new Error('markers not found');
const inject = "import { runPipeline } from './recon-pipeline.js';\nimport { prependExtraPathToEnvPath } from './modules/tool-path.js';\n\n";
s = s.slice(0, start) + inject + s.slice(end);
fs.writeFileSync(p, s, 'utf8');
console.log('Stripped old runPipeline, inserted imports');
