#!/usr/bin/env node
/**
 * Gera `mitre-attack/recon-bundle.json` a partir do clone local MITRE CTI
 * (`mitre-attack/cti/enterprise-attack/`), limitado a tácticas
 * reconnaissance, resource-development e initial-access.
 *
 * Uso: node server/scripts/extract-mitre-recon-bundle.mjs
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '../..');
const entRoot = path.join(projectRoot, 'mitre-attack/cti/enterprise-attack');
const outFile = path.join(projectRoot, 'mitre-attack/recon-bundle.json');

const ALLOWED_PHASES = new Set(['reconnaissance', 'resource-development', 'initial-access']);

function techniqueUrl(extId) {
  if (!extId || typeof extId !== 'string' || !extId.startsWith('T')) return null;
  const parts = extId.split('.');
  if (parts.length === 1) return `https://attack.mitre.org/techniques/${extId}/`;
  const base = parts[0];
  return `https://attack.mitre.org/techniques/${base}/${extId}/`;
}

function tacticUrl(ta) {
  if (!ta || typeof ta !== 'string' || !ta.startsWith('TA')) return null;
  return `https://attack.mitre.org/tactics/${ta}/`;
}

function readStixObjects(dir, type) {
  const sub = path.join(entRoot, dir);
  if (!fs.existsSync(sub)) return [];
  const files = fs.readdirSync(sub).filter((f) => f.endsWith('.json'));
  const out = [];
  for (const f of files) {
    let j;
    try {
      j = JSON.parse(fs.readFileSync(path.join(sub, f), 'utf8'));
    } catch {
      continue;
    }
    const objs = Array.isArray(j.objects) ? j.objects : [];
    const o = objs.find((x) => x.type === type);
    if (o) out.push(o);
  }
  return out;
}

function main() {
  if (!fs.existsSync(entRoot)) {
    console.error(`Pasta CTI inexistente: ${entRoot}`);
    console.error('Coloca o repositório MITRE/cti em mitre-attack/cti/ e volta a correr.');
    process.exit(1);
  }

  const tacticObjs = readStixObjects('x-mitre-tactic', 'x-mitre-tactic');
  const tactics = [];
  for (const o of tacticObjs) {
    const sn = o.x_mitre_shortname;
    if (!ALLOWED_PHASES.has(sn)) continue;
    const er = (o.external_references || []).find((r) => r.source_name === 'mitre-attack' && r.external_id);
    const ta = er?.external_id;
    if (!ta) continue;
    tactics.push({
      id: ta,
      name: o.name || ta,
      shortname: sn,
      url: tacticUrl(ta),
    });
  }
  tactics.sort((a, b) => a.id.localeCompare(b.id));

  const apDir = path.join(entRoot, 'attack-pattern');
  const apFiles = fs.existsSync(apDir) ? fs.readdirSync(apDir).filter((f) => f.endsWith('.json')) : [];
  const techniques = [];

  for (const f of apFiles) {
    let j;
    try {
      j = JSON.parse(fs.readFileSync(path.join(apDir, f), 'utf8'));
    } catch {
      continue;
    }
    const objs = Array.isArray(j.objects) ? j.objects : [];
    const o = objs.find((x) => x.type === 'attack-pattern');
    if (!o) continue;
    if (o.revoked || o.x_mitre_deprecated) continue;
    const phases = (o.kill_chain_phases || [])
      .map((p) => p.phase_name)
      .filter((p) => ALLOWED_PHASES.has(p));
    if (!phases.length) continue;
    const er = (o.external_references || []).find((r) => r.source_name === 'mitre-attack' && r.external_id);
    const extId = er?.external_id;
    if (!extId || !String(extId).startsWith('T')) continue;
    techniques.push({
      id: extId,
      name: o.name || extId,
      phases: [...new Set(phases)].sort(),
      url: techniqueUrl(extId),
    });
  }
  techniques.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

  const payload = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    scope: 'enterprise-attack',
    phases: [...ALLOWED_PHASES].sort(),
    tactics,
    techniques,
  };

  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, `${JSON.stringify(payload)}\n`, 'utf8');
  console.log(`Escrito ${outFile} (${techniques.length} técnicas, ${tactics.length} tácticas).`);
}

main();
