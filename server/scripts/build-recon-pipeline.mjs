/**
 * Gera server/recon-pipeline.js a partir da cópia de referência em
 * `vendor/recon-pipeline-regen/ghostrecon-server-index.js` (actualiza esse ficheiro se tiveres uma nova fonte).
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..', '..');
const src = path.join(root, 'vendor', 'recon-pipeline-regen', 'ghostrecon-server-index.js');
const out = path.join(root, 'server', 'recon-pipeline.js');

const lines = fs.readFileSync(src, 'utf8').split('\n');

// Linhas 1–6: load-env, express, path, fs, fileURLToPath, randomBytes (servidor; não vão para o pipeline).
// Linhas 7–111: imports de módulos até ghost-kb-sync (alinhar com vendor/recon-pipeline-regen/ghostrecon-server-index.js).
const importLines = [...lines.slice(6, 111)];

const header = `/**
 * Recon completo (código derivado do servidor recon legado), **sem** Shannon nem PentestGPT.
 * Regenerar: \`node server/scripts/build-recon-pipeline.mjs\` (fonte: vendor/recon-pipeline-regen/ghostrecon-server-index.js)
 */
import 'dotenv/config';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
`;

// Após CORS/json: helpers = aiAutoReportsServerAllowed … até ao `}` que fecha buildPipelineExportPayloadForAi (L209–324; L325 é async runPipeline).
const helpers = lines.slice(208, 324).join('\n');

// runPipeline: L325–2319 (fim exclusivo 2319 = inclui `}` de runPipeline; L2320 é app.post).
let body = lines.slice(324, 2319).join('\n');

body = body.replace(
  /shannonPrecheck = true,\n\s*shannonSkipDepsVerify = false,\n\s*shannonGithubRepos = null,\n\s*pentestgptUrl: pentestgptUrlOverride = null,\n/g,
  'manualGithubReposRaw = null,\n',
);

body = body.replace(
  /const manualGithubRepos = parseGithubManualRepoList\(shannonGithubRepos\);/g,
  'const manualGithubRepos = parseGithubManualRepoList(manualGithubReposRaw);',
);

// Shannon-only clone branch (GitHub off)
body = body.replace(
  /\} else if \(manualGithubRepos\.length && modules\.includes\('shannon_whitebox'\)\) \{[\s\S]*?\} else if \(manualGithubRepos\.length\) \{/,
  '} else if (manualGithubRepos.length) {',
);

// Shannon pipe placeholder
body = body.replace(
  /if \(!modules\.includes\('shannon_whitebox'\)\) \{\n\s*emit\(\{ type: 'pipe', name: 'shannon', state: 'skip' \}\);\n\s*\} else \{[\s\S]*?\}\n\n\s*\/\/ ── VERIFY/g,
  "emit({ type: 'pipe', name: 'shannon', state: 'skip' });\n\n  // ── VERIFY",
);

// Shannon white-box block (after report templates)
body = body.replace(
  /\/\/ Shannon white-box: após priorização[\s\S]*?applyPrioritizationV2\(findings, bountyCtx\);\n\s*\}\n\s*\}\n\n\s*const modulesForDb/m,
  'const modulesForDb',
);

// PentestGPT block
body = body.replace(
  /let pentestgptSummary = null;\n\s*progress\(98\);\n\s*if \(modules\.includes\('pentestgpt_validate'\)\) \{[\s\S]*?\} else \{\n\s*emit\(\{ type: 'pipe', name: 'pentestgpt', state: 'skip' \}\);\n\s*\}\n\n\s*progress\(100\);/m,
  'const pentestgptSummary = null;\n  progress(98);\n  emit({ type: \'pipe\', name: \'pentestgpt\', state: \'skip\' });\n\n  progress(100);',
);

// Webhook: remove shannonSummary / pentestgptSummary keys if still referenced — replace postReconWebhook payload
body = body.replace(/shannonSummary,\n\s*pentestgptSummary,/g, '');

const footer = `
export { runPipeline };
`;

const importsJoined = importLines.join('\n').replace(/^import '\.\/load-env\.js';$/m, '');

const full = `${header}
${importsJoined}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

${helpers}

${body}
${footer}`;

fs.writeFileSync(out, full, 'utf8');
console.log('Wrote', out, 'bytes', full.length);
