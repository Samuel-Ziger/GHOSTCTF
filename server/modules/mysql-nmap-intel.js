import { hostLiteralForUrl } from './recon-target.js';

/**
 * Gera achados `intel` de follow-up quando o nmap reporta 3306/tcp (MySQL típico).
 * Não executa scans extra — só orientação para triagem manual (alvo autorizado).
 *
 * @param {Array<{ host?: string, port?: string, proto?: string, name?: string, product?: string, version?: string }>} rows
 * @returns {object[]}
 */
export function buildMysql3306IntelFindings(rows) {
  const seen = new Set();
  const out = [];
  for (const row of rows || []) {
    if (!row) continue;
    if (String(row.port) !== '3306') continue;
    if (String(row.proto || 'tcp').toLowerCase() !== 'tcp') continue;
    const host = String(row.host || '')
      .trim()
      .toLowerCase();
    if (!host || host === 'unknown') continue;
    if (seen.has(host)) continue;
    seen.add(host);

    const hl = hostLiteralForUrl(host);
    const svc = [row.name, row.product, row.version].filter(Boolean).join(' ').trim() || '3306/tcp aberto';
    const ver = row.version ? String(row.version).slice(0, 40) : '';

    out.push({
      type: 'intel',
      prio: 'med',
      score: 59,
      value: `MySQL/MariaDB (3306/tcp) em ${host} — ${svc.slice(0, 96)}`,
      meta: [
        `mysql_cli=mysql -h ${hl} -P 3306 -u root -p`,
        `nmap_scripts=nmap -p3306 --script "mysql-info,mysql-empty-password,mysql-users,mysql-variables,mysql-audit" ${hl}`,
        ver ? `versao_nmap=${ver}` : null,
        `sqlmap_dsn=sqlmap -d "mysql://USER:PASS@${hl}:3306/dbname" --batch (se tiveres credenciais)`,
        `nota=Só enumeração permitida pelo programa de bounty / contrato`,
      ]
        .filter(Boolean)
        .join(' · '),
    });
  }
  return out;
}
