"""
GHOST CodeScan — Análise Estática de Segurança
Lê repositório local, aplica regras estáticas por linguagem
e usa o LLM para análise profunda contextual.
"""

import os, re, json
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict

# ─────────────────────────────────────────────────────
#  EXTENSÕES SUPORTADAS
# ─────────────────────────────────────────────────────
LANG_MAP = {
    ".py":   "python",
    ".java": "java",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".vue":  "vue",
    ".php":  "php",
    ".sh":   "bash",
    ".bash": "bash",
    ".go":   "go",
    ".c":    "c",
    ".cpp":  "cpp",
    ".cc":   "cpp",
    ".cxx":  "cpp",
    ".c++":  "cpp",
    ".h":    "c",
    ".hpp":  "cpp",
    ".hxx":  "cpp",
    ".asm":  "assembly",
    ".s":    "assembly",
    ".S":    "assembly",
    ".nasm": "assembly",
    ".nes":  "assembly",
    ".rb":   "ruby",
    ".rs":   "rust",
    ".xml":  "xml",
    ".yml":  "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".env":  "env",
    ".sql":  "sql",
    ".tf":   "terraform",
    ".conf": "config",
    ".ini":  "config",
    ".toml": "toml",
}

IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".idea", ".vscode", "target", "vendor",
    ".gradle", ".mvn", "coverage", ".nyc_output", "clone"
}

IGNORE_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".zip",
    ".tar", ".gz", ".class", ".pyc", ".min.js", ".lock"
}

MAX_FILE_SIZE = 512 * 1024   # 512KB por arquivo
MAX_FILES     = 300           # máximo de arquivos no scan
MAX_LINES_LLM = 400           # máximo de linhas enviadas ao LLM por arquivo

# ─────────────────────────────────────────────────────
#  REGRAS ESTÁTICAS
# ─────────────────────────────────────────────────────
@dataclass
class StaticFinding:
    file:     str
    line:     int
    lang:     str
    rule:     str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title:    str
    snippet:  str
    cwe:      str = ""
    owasp:    str = ""

# Padrão: (regex, severity, title, cwe, owasp)
RULES_GLOBAL = [
    # Secrets / hardcoded creds
    (r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth_token|access_token|private_key|secret_key)\s*[=:]\s*["\'][^"\']{4,}["\']',
     "CRITICAL","Credencial hardcoded detectada","CWE-798","A02"),
    (r'(?i)(aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16})',
     "CRITICAL","AWS credential exposta","CWE-798","A02"),
    (r'(?i)(ghp_[a-zA-Z0-9]{36}|github_token\s*[=:]\s*["\'][^"\']+["\'])',
     "CRITICAL","GitHub token exposto","CWE-798","A02"),
    (r'(?i)(sk-[a-zA-Z0-9]{48})',
     "CRITICAL","OpenAI API key exposta","CWE-798","A02"),
    (r'(?i)(-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)',
     "CRITICAL","Chave privada hardcoded","CWE-321","A02"),
    (r'(?i)(jdbc:[a-z]+://[^:]+:[^@]+@)',
     "HIGH","Connection string com credenciais","CWE-798","A02"),
    # SQL Injection
    (r'(?i)(execute|query|cursor\.execute)\s*\(\s*[f"\'](.*(%s|{|}|\+|format))',
     "HIGH","Possível SQL Injection (concatenação/format)","CWE-89","A03"),
    (r'(?i)(\"select|\"insert|\"update|\"delete|\"drop).*(\"|\+\s*\w)',
     "HIGH","Query SQL construída por concatenação","CWE-89","A03"),
    # XSS / Output unsafe
    (r'(?i)(innerHTML|outerHTML|document\.write)\s*[=\(]',
     "MEDIUM","Possível XSS via innerHTML/document.write","CWE-79","A03"),
    (r'(?i)eval\s*\(',
     "HIGH","Uso de eval() — execução de código dinâmico","CWE-95","A03"),
    # Command injection
    (r'(?i)(os\.system|subprocess\.(call|run|Popen)|exec\(|shell=True)',
     "HIGH","Execução de comando do sistema — verificar input","CWE-78","A03"),
    (r'(?i)(Runtime\.getRuntime\(\)\.exec\()',
     "HIGH","Java Runtime.exec() — possível injeção de comando","CWE-78","A03"),
    # Path traversal
    (r'(?i)(open\(|fopen\(|readFile\().*(request\.|req\.|input|param|argv|GET|POST)',
     "HIGH","Possível path traversal — input em operação de arquivo","CWE-22","A01"),
    # Insecure deserialization
    (r'(?i)(pickle\.loads|pickle\.load|yaml\.load\(|unserialize\(|ObjectInputStream)',
     "HIGH","Deserialização insegura","CWE-502","A08"),
    # Crypto fraco
    (r'(?i)\b(md5|sha1)\s*[\(\.]',
     "MEDIUM","Hash fraco (MD5/SHA1) — usar SHA-256+","CWE-328","A02"),
    (r'(?i)(DES|RC4|ECB|3DES)\b',
     "MEDIUM","Algoritmo criptográfico fraco","CWE-327","A02"),
    (r'(?i)(random\.(random|randint|choice)|Math\.random\(\))',
     "LOW","PRNG não criptográfico — não usar para tokens/senhas","CWE-338","A02"),
    # SSRF hints
    (r'(?i)(requests\.(get|post|put)|urllib|fetch|curl|http\.get)\s*\(.*\+',
     "MEDIUM","Request HTTP com URL dinâmica — verificar SSRF","CWE-918","A10"),
    # Debug / info disclosure
    (r'(?i)(print\s*\(.*password|console\.log\(.*token|System\.out\.print.*secret)',
     "MEDIUM","Log de informação sensível","CWE-532","A09"),
    (r'(?i)(debug\s*=\s*True|DEBUG\s*=\s*True)',
     "MEDIUM","Debug mode ativo em produção","CWE-215","A05"),
    # CORS / headers
    (r'(?i)(Access-Control-Allow-Origin["\']?\s*:\s*["\']?\*)',
     "MEDIUM","CORS wildcard — permite qualquer origem","CWE-942","A05"),
    # XXE
    (r'(?i)(XMLInputFactory|SAXParserFactory|DocumentBuilderFactory)',
     "LOW","Parser XML — verificar configuração contra XXE","CWE-611","A05"),
    # JWT
    (r'(?i)(verify\s*=\s*False|algorithms\s*=\s*\[.*none.*\])',
     "HIGH","JWT sem verificação ou algoritmo none","CWE-347","A02"),
    # Env files
    (r'(?i)^(DB_PASS|DATABASE_URL|SECRET_KEY|JWT_SECRET)\s*=\s*.+',
     "INFO","Variável de ambiente sensível — não versionar .env","CWE-312","A02"),
]

RULES_BY_LANG = {
    "python": [
        (r'(?i)flask\.run\(.*debug\s*=\s*True', "HIGH","Flask debug=True em código","CWE-215","A05"),
        (r'(?i)app\.config\[.SECRET_KEY.\]\s*=\s*["\'][^"\']{1,20}["\']', "HIGH","Flask SECRET_KEY fraca/hardcoded","CWE-798","A02"),
        (r'@app\.route.*methods.*GET.*delete|@app\.route.*methods.*GET.*drop', "MEDIUM","Operação destrutiva via GET","CWE-650","A01"),
        (r'(?i)cursor\.execute\(.*%.*,\s*request', "HIGH","SQLi — input direto em execute()","CWE-89","A03"),
    ],
    "java": [
        (r'@RequestMapping.*\{.*\}.*String\s+\w+\s*\)', "LOW","Spring path variable — verificar validação","CWE-20","A01"),
        (r'(?i)statement\.execute\(.*\+\s*(req|request|param)', "HIGH","SQLi em Statement Java","CWE-89","A03"),
        (r'(?i)\.setValidating\(false\)|setFeature.*XMLConstants', "LOW","XML parser sem validação","CWE-611","A05"),
        (r'(?i)new\s+ObjectInputStream', "HIGH","Java deserialization insegura","CWE-502","A08"),
        (r'(?i)@CrossOrigin\(origins\s*=\s*"\*"', "MEDIUM","CORS wildcard em controller Spring","CWE-942","A05"),
    ],
    "javascript": [
        (r'(?i)require\s*\(\s*(\'|\")child_process', "HIGH","child_process importado — verificar uso","CWE-78","A03"),
        (r'(?i)window\.location\s*=.*location\.(search|hash)', "MEDIUM","Open redirect via location","CWE-601","A01"),
        (r'(?i)(localStorage|sessionStorage)\.setItem\(.*password', "HIGH","Senha em localStorage","CWE-312","A02"),
        (r'(?i)JSON\.parse\(.*req\.(body|query|params)', "MEDIUM","Parse JSON de input não validado","CWE-20","A01"),
        (r'(?i)(prototype\[|__proto__\[)', "HIGH","Possível prototype pollution","CWE-1321","A03"),
    ],
    "php": [
        (r'(?i)\$_(GET|POST|REQUEST|COOKIE)\[.*\]\s*without_sanitize', "HIGH","Input PHP sem sanitização","CWE-20","A01"),
        (r'(?i)(echo|print)\s+\$_(GET|POST|REQUEST|COOKIE)', "HIGH","XSS direto — echo de input","CWE-79","A03"),
        (r'(?i)mysql_query\s*\(.*\$_(GET|POST)', "CRITICAL","SQLi direto — mysql_query com input","CWE-89","A03"),
        (r'(?i)include\s*\(\s*\$_(GET|POST)', "CRITICAL","LFI/RFI — include com input do usuário","CWE-98","A01"),
        (r'(?i)system\s*\(\s*\$_(GET|POST)', "CRITICAL","RCE — system() com input do usuário","CWE-78","A03"),
        (r'(?i)unserialize\s*\(\s*\$_(GET|POST|COOKIE)', "CRITICAL","PHP unserialize com input — RCE","CWE-502","A08"),
    ],
    "bash": [
        (r'\$\{.*:-.*\}.*rm\s+-rf', "HIGH","Expansão de variável em rm -rf","CWE-78","A03"),
        (r'eval\s+"\$', "HIGH","eval com variável — injeção de comando","CWE-78","A03"),
        (r'curl.*\$[A-Z_]+.*\|\s*(bash|sh)', "HIGH","Pipe curl para shell com variável","CWE-494","A08"),
        (r'chmod\s+777', "MEDIUM","Permissão 777 — muito permissiva","CWE-732","A01"),
    ],
    "env": [
        (r'^[A-Z_]+=.{1,}', "INFO","Variável de ambiente definida — verificar se está em .gitignore","CWE-312","A02"),
    ],
    "sql": [
        (r'(?i)GRANT ALL', "MEDIUM","GRANT ALL — privilégio excessivo","CWE-272","A01"),
        (r'(?i)DROP TABLE', "HIGH","DROP TABLE no código — verificar contexto","CWE-89","A03"),
    ],

    # ─── C / C++ ───────────────────────────────────────────────────────────
    "c": [
        # Buffer overflow — funções clássicamente inseguras
        (r'\b(gets|gets_s)\s*\(',                                              "CRITICAL","gets() — buffer overflow garantido, não tem limite","CWE-120","A03"),
        (r'\bstrcpy\s*\(',                                                     "HIGH",   "strcpy() sem limite — use strncpy/strlcpy","CWE-120","A03"),
        (r'\bstrcat\s*\(',                                                     "HIGH",   "strcat() sem limite — use strncat/strlcat","CWE-120","A03"),
        (r'\bsprintf\s*\(',                                                    "HIGH",   "sprintf() sem limite — use snprintf","CWE-120","A03"),
        (r'\bvsprintf\s*\(',                                                   "HIGH",   "vsprintf() sem limite — use vsnprintf","CWE-120","A03"),
        (r'\bscanf\s*\(\s*"[^"]*%s',                                          "HIGH",   "scanf %s sem largura — buffer overflow","CWE-120","A03"),
        (r'\bmemcpy\s*\(.*,.*,\s*\w+\s*\)',                                   "MEDIUM", "memcpy — verificar se tamanho é validado contra destino","CWE-120","A03"),
        (r'\bmemmove\s*\(.*,.*,\s*\w+\s*\)',                                  "LOW",    "memmove — verificar bounds do destino","CWE-120","A03"),

        # Format string
        (r'\b(printf|fprintf|syslog|wprintf)\s*\(\s*\w+\s*[,\)]',            "HIGH",   "Format string controlado por variável — CWE-134","CWE-134","A03"),
        (r'\b(printf|fprintf)\s*\(\s*(stdin|argv\[|getenv\()',                "CRITICAL","Format string com input externo direto","CWE-134","A03"),

        # Integer overflow / underflow
        (r'\b(malloc|calloc|realloc)\s*\(\s*\w+\s*\*\s*\w+\s*\)',            "HIGH",   "Multiplicação em malloc — possível integer overflow → heap overflow","CWE-190","A03"),
        (r'\b(malloc|calloc)\s*\(\s*\w+\s*\+\s*\w+\s*\)',                    "MEDIUM", "Adição em malloc — verificar overflow antes","CWE-190","A03"),
        (r'\(int\)\s*strlen\b|\(int\)\s*sizeof\b',                            "MEDIUM", "Cast de size_t para int — possível truncation/signed overflow","CWE-190","A03"),

        # Use-after-free / double-free
        (r'free\s*\(\s*(\w+)\s*\).*\1\s*[^=]',                               "HIGH",   "Possível use-after-free — variável usada após free()","CWE-416","A03"),
        (r'free\s*\(\s*\w+\s*\);\s*\n.*free\s*\(',                           "HIGH",   "Possível double-free","CWE-415","A03"),
        (r'free\s*\(\s*(\w+)\s*\)(?!\s*\n\s*\1\s*=\s*NULL)',                 "MEDIUM", "free() sem NULL — hábito seguro: ptr = NULL após free","CWE-416","A03"),

        # Null dereference
        (r'\b(malloc|calloc|realloc)\s*\([^)]+\)\s*;(?!\s*if)',               "MEDIUM", "malloc sem verificação de NULL — null deref potencial","CWE-476","A03"),
        (r'=\s*malloc\([^)]+\);\s*\*',                                        "MEDIUM", "Deref imediato após malloc sem NULL check","CWE-476","A03"),

        # Race conditions / TOCTOU
        (r'\b(access|stat)\s*\(.*\).*\b(open|fopen|execve)\s*\(',            "HIGH",   "TOCTOU — access()/stat() seguido de open() — race condition","CWE-367","A04"),

        # Dangerous functions
        (r'\bsystem\s*\(',                                                     "HIGH",   "system() — injeção de comando se input não sanitizado","CWE-78","A03"),
        (r'\bexecve?\s*\(',                                                    "HIGH",   "exec() — verificar que argumentos não vêm de input","CWE-78","A03"),
        (r'\bpopen\s*\(',                                                      "HIGH",   "popen() — injeção de comando se input não sanitizado","CWE-78","A03"),
        (r'\bsetuid\s*\(\s*0\s*\)',                                            "HIGH",   "setuid(0) — elevação para root","CWE-250","A01"),
        (r'\bchmod\s*\(.*0777',                                               "MEDIUM", "chmod 0777 — permissões excessivas","CWE-732","A01"),
        (r'\btmpnam\s*\(\|tempnam\s*\(',                                       "MEDIUM", "tmpnam/tempnam — race condition em criação de temp file","CWE-377","A04"),

        # Crypto / random
        (r'\brand\s*\(\|srand\s*\(time',                                       "MEDIUM", "rand()/srand(time) — PRNG não criptográfico","CWE-338","A02"),
        (r'\bDES_\w+\s*\(',                                                    "HIGH",   "DES — algoritmo criptográfico fraco","CWE-327","A02"),
        (r'\bMD5\s*\(',                                                        "MEDIUM", "MD5 — hash criptograficamente inseguro","CWE-328","A02"),

        # Signed/unsigned comparison
        (r'\bstrlen\s*\(.*\)\s*[<>]=?\s*-',                                   "HIGH",   "Comparação size_t com negativo — sempre falsa/verdadeira","CWE-195","A03"),
    ],

    "cpp": [
        # Tudo do C +
        (r'\b(gets|gets_s)\s*\(',                                              "CRITICAL","gets() — buffer overflow","CWE-120","A03"),
        (r'\bstrcpy\s*\(',                                                     "HIGH",   "strcpy() — use std::string ou strncpy","CWE-120","A03"),
        (r'\bsprintf\s*\(',                                                    "HIGH",   "sprintf() — use snprintf ou std::format","CWE-120","A03"),
        (r'\b(printf|fprintf)\s*\(\s*\w+\s*[,\)]',                            "HIGH",   "Format string controlado por variável","CWE-134","A03"),
        (r'\b(malloc|calloc|realloc)\s*\(\s*\w+\s*\*\s*\w+\s*\)',            "HIGH",   "Multiplicação em malloc — integer overflow","CWE-190","A03"),

        # C++ específico
        (r'\bnew\s+\w+\[.*\]\s*;(?!\s*(if|try))',                             "MEDIUM", "new[] sem try/catch — exception → memory leak","CWE-401","A03"),
        (r'delete\s+(\w+).*\1[^=]',                                           "HIGH",   "Possível use-after-delete","CWE-416","A03"),
        (r'\bstd::cin\s*>>\s*\w+\s*;',                                        "LOW",    "cin >> sem verificação de tamanho — cuidado com tipos fixos","CWE-20","A01"),
        (r'\b(dynamic_cast|static_cast|reinterpret_cast)<',                   "LOW",    "Cast explícito — verificar type safety","CWE-704","A03"),
        (r'\bconst_cast<',                                                     "MEDIUM", "const_cast — remove constness, cuidado com UB","CWE-704","A03"),
        (r'catch\s*\(\s*\.\.\.\s*\)',                                          "LOW",    "catch(...) silencia todas as exceções — dificulta debug","CWE-390","A09"),
        (r'\bauto_ptr<',                                                       "MEDIUM", "auto_ptr depreciado — usar unique_ptr","CWE-401","A03"),
        (r'shared_ptr.*raw_pointer|\.get\(\)\s*delete',                       "HIGH",   "Mistura de raw pointer com shared_ptr — double free","CWE-415","A03"),
        (r'\bthrow\s*;\s*$',                                                  "LOW",    "Re-throw sem contexto — verificar se intencional","CWE-390","A09"),

        # Concorrência
        (r'(?i)\bstd::thread\b.*\blambda\b|\[&\]\s*\(',                       "MEDIUM", "Lambda com capture-by-ref em thread — race condition","CWE-362","A04"),
        (r'(?i)\bvolatile\b.*\bflag\b|\bflag\b.*\bvolatile\b',               "MEDIUM", "volatile como sync primitivo — usar std::atomic","CWE-362","A04"),

        # Memory
        (r'\bnew\s+\w+\(.*\)\s*;\s*//.*todo|fixme',                          "LOW",    "Alocação com TODO/FIXME próximo — verificar gerenciamento","CWE-401","A03"),
        (r'\bmemset\s*\(.*,\s*0\s*,\s*sizeof\s*\(\s*\w+\s*\*\s*\)\s*\)',    "MEDIUM", "memset com sizeof(ponteiro) em vez de sizeof(*ponteiro)","CWE-131","A03"),
    ],

    # ─── ASSEMBLY ──────────────────────────────────────────────────────────
    "assembly": [
        # Stack manipulation
        (r'(?i)\bret\b\s*$',                                                   "INFO",   "RET — verificar que stack está balanceada","CWE-121","A03"),
        (r'(?i)\bcall\b.*\[.*\+.*\]',                                         "HIGH",   "Indirect CALL via offset — possível control-flow hijack","CWE-691","A03"),
        (r'(?i)\bjmp\b.*\[.*\+.*\]|\bjmp\b.*\[.*eax|rbx|rcx|rdx',           "HIGH",   "Indirect JMP via registrador — possível ROP/JOP gadget","CWE-691","A03"),

        # Gadgets comuns
        (r'(?i)\bpop\s+(rsp|esp)\b',                                          "HIGH",   "POP RSP/ESP — stack pivot clássico para ROP","CWE-119","A03"),
        (r'(?i)\bxchg\s+(rsp|esp),\s*\w+|\bxchg\s+\w+,\s*(rsp|esp)',        "HIGH",   "XCHG com RSP/ESP — stack pivot","CWE-119","A03"),
        (r'(?i)\bleave\b\s*\n\s*\bret\b',                                    "MEDIUM", "LEAVE + RET — gadget clássico de stack pivot","CWE-119","A03"),
        (r'(?i)\badd\s+(rsp|esp),\s*0x[0-9a-f]+\s*\n\s*\bret\b',           "MEDIUM", "ADD RSP + RET — gadget de stack adjustment","CWE-119","A03"),

        # Shellcode patterns
        (r'(?i)\bint\s+0x80\b',                                               "HIGH",   "int 0x80 — syscall x86 (shellcode/exploit)","CWE-78","A03"),
        (r'(?i)\bsyscall\b',                                                  "MEDIUM", "syscall direto — verificar contexto (shellcode?)","CWE-78","A03"),
        (r'(?i)\bsysenter\b',                                                 "MEDIUM", "sysenter — syscall alternativa x86","CWE-78","A03"),
        (r'(?i)\b(xor|sub)\s+(eax|rax),\s*(eax|rax)\b',                     "INFO",   "XOR/SUB reg,reg — zero-out clássico (comum em shellcode)","CWE-NULL",""),
        (r'(?i)\bpush\s+0x[0-9a-f]{6,}\b',                                  "LOW",    "PUSH de valor grande — verificar se é endereço hardcoded","CWE-NULL",""),

        # NOP sled
        (r'(?i)(\bnop\b\s*\n){4,}',                                          "MEDIUM", "NOP sled detectado (4+ NOPs consecutivos)","CWE-NULL",""),

        # Dangerous patterns
        (r'(?i)\bwrmsr\b',                                                    "HIGH",   "WRMSR — escrita em Model-Specific Register (kernel/ring0)","CWE-269","A01"),
        (r'(?i)\b(lgdt|lidt|lldt)\b',                                        "HIGH",   "LGDT/LIDT/LLDT — carregamento de descriptor table (ring0)","CWE-269","A01"),
        (r'(?i)\bcli\b\s*\n.*\bsti\b',                                       "MEDIUM", "CLI/STI — desabilita/habilita interrupções","CWE-400","A01"),
        (r'(?i)\bin\s+(al|ax|eax),\s*(0x[0-9a-f]+|\w+)',                    "MEDIUM", "IN — leitura de porta I/O (ring0)","CWE-269","A01"),
        (r'(?i)\bout\s+(0x[0-9a-f]+|\w+),\s*(al|ax|eax)',                   "MEDIUM", "OUT — escrita em porta I/O (ring0)","CWE-269","A01"),

        # Memory
        (r'(?i)\b(rep\s+movs|rep\s+stos)\b',                                 "LOW",    "REP MOVS/STOS — operação em bloco, verificar limite","CWE-120","A03"),
        (r'(?i)\bmov\s+\[(r|e)sp\s*[-+]\s*0x[0-9a-f]+\],',                 "LOW",    "Escrita em stack via offset — verificar se dentro do frame","CWE-121","A03"),

        # Obfuscation hints
        (r'(?i)\brol\b|\bror\b|\bshl\b|\bshr\b.*\bxor\b',                   "INFO",   "Rotação/shift + XOR — padrão de ofuscação ou criptografia custom","CWE-NULL",""),
        (r'(?i)\bpusha\b|\bpushad\b',                                        "INFO",   "PUSHA/PUSHAD — salva todos registradores (comum em shellcode/packer)","CWE-NULL",""),
        (r'(?i)\bcall\s+\$\+5|\bcall\s+0x0\b',                              "HIGH",   "CALL $+5 / CALL 0 — técnica para obter EIP/RIP (shellcode clássico)","CWE-NULL",""),
        (r'(?i)\bfnstenv\b|\bfstenv\b',                                     "HIGH",   "FNSTENV/FSTENV — técnica eggnhunter/shellcode para obter EIP","CWE-NULL",""),
    ],
}

# ─────────────────────────────────────────────────────
#  SCANNER
# ─────────────────────────────────────────────────────
class RepoScanner:

    def scan_file(self, filepath: str) -> list[StaticFinding]:
        """Aplica regras estáticas em um arquivo"""
        path = Path(filepath)
        ext  = path.suffix.lower()

        # Ignora binários e arquivos muito grandes
        if ext in IGNORE_EXTS: return []
        if path.stat().st_size > MAX_FILE_SIZE: return []

        lang = LANG_MAP.get(ext, "")
        if not lang and path.name not in (".env", ".env.example", ".env.local"):
            # tenta detectar por nome
            if path.name == ".env" or path.name.startswith(".env"):
                lang = "env"

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except: return []

        findings = []
        all_rules = list(RULES_GLOBAL)
        if lang in RULES_BY_LANG:
            all_rules.extend(RULES_BY_LANG[lang])

        seen = set()  # dedup por (linha, regra)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "*", "/*")): continue

            for pattern, sev, title, cwe, owasp in all_rules:
                if re.search(pattern, line):
                    key = (i, title)
                    if key in seen: continue
                    seen.add(key)
                    findings.append(StaticFinding(
                        file=str(path),
                        line=i,
                        lang=lang or ext,
                        rule=pattern[:60],
                        severity=sev,
                        title=title,
                        snippet=stripped[:200],
                        cwe=cwe,
                        owasp=owasp
                    ))

        return findings

    def walk_repo(self, root: str, include_exts: set = None,
                  exclude_paths: list = None) -> dict:
        """
        Percorre o repositório e retorna:
        - findings estáticos
        - mapa de arquivos por linguagem
        - conteúdo de arquivos para análise LLM
        """
        root_path = Path(root)
        if not root_path.exists():
            raise FileNotFoundError(f"Repositório não encontrado: {root}")

        all_findings: list[StaticFinding] = []
        files_by_lang: dict[str, list] = {}
        file_contents: list[dict]       = []
        file_count = 0

        exclude_set = set(exclude_paths or [])

        for dirpath, dirnames, filenames in os.walk(root_path):
            # Remove dirs ignorados
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and d not in exclude_set]

            for fname in filenames:
                if file_count >= MAX_FILES: break

                fpath = Path(dirpath) / fname
                ext   = fpath.suffix.lower()

                # Ignora por extensão
                if any(str(fpath).endswith(e) for e in IGNORE_EXTS): continue
                if include_exts and ext not in include_exts: continue
                if fpath.stat().st_size > MAX_FILE_SIZE: continue

                lang = LANG_MAP.get(ext, "")
                if not lang and fname.startswith(".env"):
                    lang = "env"
                if not lang: continue  # só analisa linguagens conhecidas

                # Scan estático
                findings = self.scan_file(str(fpath))
                all_findings.extend(findings)

                # Organiza por linguagem
                files_by_lang.setdefault(lang, []).append(str(fpath))

                # Conteúdo para LLM (apenas arquivos com código real)
                if lang not in ("json", "yaml", "toml", "config", "env"):
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            content_lines = f.readlines()
                        if len(content_lines) > 5:  # ignora arquivos triviais
                            file_contents.append({
                                "path": str(fpath.relative_to(root_path)),
                                "lang": lang,
                                "lines": len(content_lines),
                                "content": "".join(content_lines[:MAX_LINES_LLM])
                            })
                    except: pass

                file_count += 1

        # Ordena findings por severidade
        sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        all_findings.sort(key=lambda f: sev_order.get(f.severity, 5))

        return {
            "root": str(root_path),
            "files_scanned": file_count,
            "files_by_lang": {k: len(v) for k, v in files_by_lang.items()},
            "static_findings": [asdict(f) for f in all_findings],
            "static_findings_count": len(all_findings),
            "severity_summary": {
                s: len([f for f in all_findings if f.severity == s])
                for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
            },
            "file_contents": file_contents,  # para análise LLM
        }

    def build_llm_prompt(self, scan_result: dict, focus: str = "all",
                         target_file: str = None) -> str:
        """Monta prompt para análise LLM profunda"""
        root = scan_result["root"]
        findings = scan_result["static_findings"]
        contents = scan_result["file_contents"]

        if target_file:
            # Foco em arquivo específico
            contents = [c for c in contents if target_file in c["path"]]
            findings = [f for f in findings if target_file in f["file"]]

        # Limita conteúdo enviado ao LLM
        total_chars = 0
        selected_contents = []
        # Prioriza arquivos com findings
        files_with_findings = {f["file"] for f in findings}
        priority = [c for c in contents if any(fw in c["path"] for fw in
                    [Path(f).name for f in files_with_findings])]
        rest = [c for c in contents if c not in priority]

        for c in priority + rest:
            chars = len(c["content"])
            if total_chars + chars > 60000: break  # ~60k chars max
            selected_contents.append(c)
            total_chars += chars

        # Prompt
        severity_summary = scan_result.get("severity_summary", {})
        prompt_parts = [
            f"## Repositório: {root}",
            f"Arquivos escaneados: {scan_result['files_scanned']}",
            f"Linguagens: {json.dumps(scan_result['files_by_lang'])}",
            f"\n### Findings Estáticos Automáticos ({len(findings)} total):",
            f"CRITICAL:{severity_summary.get('CRITICAL',0)} HIGH:{severity_summary.get('HIGH',0)} MEDIUM:{severity_summary.get('MEDIUM',0)}",
            "\n```json",
            json.dumps(findings[:30], indent=2, ensure_ascii=False),
            "```",
        ]

        if selected_contents:
            prompt_parts.append(f"\n### Código-fonte ({len(selected_contents)} arquivos):\n")
            for c in selected_contents:
                prompt_parts.append(f"\n#### {c['path']} ({c['lang']}, {c['lines']} linhas)")
                prompt_parts.append(f"```{c['lang']}\n{c['content']}\n```")

        focus_instructions = {
            "all":      "Analise segurança completa: vulnerabilidades, lógica de negócio, autenticação, autorização, criptografia, exposição de dados, injeções.",
            "sqli":     "Foco em SQL Injection: inputs em queries, ORM mal usado, stored procedures, blind injection.",
            "auth":     "Foco em autenticação e autorização: bypass, IDOR, JWT, session management, privilege escalation.",
            "secrets":  "Foco em secrets e credenciais: hardcoded, logs, variáveis, git history hints.",
            "injection":"Foco em todas as formas de injeção: SQL, Command, LDAP, XPath, template, expression language.",
            "crypto":   "Foco em criptografia: algoritmos fracos, IV fixo, ECB mode, PRNG, gestão de chaves.",
            "logic":    "Foco em falhas de lógica de negócio: race conditions, TOCTOU, bypass de fluxo, manipulação de estado.",

            # C / C++
            "memory":   """Foco em corrupção de memória (C/C++):
- Buffer overflow: stack (gets/strcpy/sprintf), heap (malloc sem validação de size, integer overflow em size)
- Use-after-free: acesso a ponteiro após free(), verificar padrões free() + uso posterior
- Double-free: múltiplos free() no mesmo ponteiro em diferentes code paths
- Null dereference: malloc sem NULL check, deref imediato
- Integer overflow/underflow: aritmética em tamanhos de buffer, signedness mismatches
- Off-by-one: loops com <= em vez de <, strlen/sizeof confusão
- Format string: printf/sprintf com argumento controlável
Para cada finding: localização exata, classe de vulnerabilidade, condição de triggering, vetor de exploração conceitual, fix.""",

            "rop":      """Foco em análise de gadgets ROP/JOP (Assembly):
- Stack pivot gadgets: pop rsp, xchg rsp,*, add rsp,N+ret, leave+ret
- Indirect call/jmp via registrador: call [rax], jmp rbx
- Syscall gadgets: int 0x80, syscall, sysenter
- CALL $+5: técnica de obtenção de RIP/EIP em shellcode
- Gadgets de escrita: mov [rax],rbx padrões
- Gadgets de leitura: mov rax,[rax]
- Controlled jumps: cmp + jne/je padrões controláveis
Para cada gadget: offset/endereço se disponível, tipo, utilidade em chain ROP, limitações.""",

            "shellcode":"""Foco em análise de shellcode (Assembly):
- NOP sleds
- Técnicas de obtenção de RIP: CALL $+5, FNSTENV, FPU tricks
- Syscall patterns: execve("/bin/sh"), read/write/open
- Técnicas de evasão: XOR encoding, rotações, character avoidance
- Egg hunters
- Staged shellcode hints
- Self-modifying code patterns
Identifica o propósito provável do shellcode e técnicas de evasão utilizadas.""",

            "race":     """Foco em race conditions e concorrência (C/C++/Assembly):
- TOCTOU: access()/stat() seguido de operação de arquivo
- Shared memory sem sincronização adequada
- volatile como substituto de atomic (C++)
- Mutex/lock ausente em seções críticas
- Thread com lambda capture-by-reference
- Sinais UNIX: signal handlers não async-signal-safe
Para cada finding: janela de race, impacto, condição para exploração.""",

            "priv":     """Foco em escalada de privilégio e execução privilegiada (C/C++/Assembly):
- setuid(0), setgid(0)
- Leitura/escrita de MSR (wrmsr/rdmsr)
- Carregamento de descriptor tables (lgdt, lidt)
- Operações de I/O privilegiadas (in/out)
- Chamadas de sistema sensíveis em contexto não confiável
- Variáveis de ambiente usadas em contexto setuid
- PATH manipulation em system()/exec*()""",
        }

        prompt_parts.append(f"\n\n## Instrução de Análise\n{focus_instructions.get(focus, focus_instructions['all'])}")
        prompt_parts.append("\nPara cada vulnerabilidade encontrada:")
        prompt_parts.append("1. **Arquivo + linha** exata")
        prompt_parts.append("2. **Tipo** de vulnerabilidade (CWE se souber)")
        prompt_parts.append("3. **Severidade** (CRITICAL/HIGH/MEDIUM/LOW)")
        prompt_parts.append("4. **Snippet** relevante do código")
        prompt_parts.append("5. **Como explorar** (PoC básico se aplicável)")
        prompt_parts.append("6. **Fix** recomendado\n")
        prompt_parts.append("Após listar vulnerabilidades: resumo de riscos e próximos passos prioritários.")

        return "\n".join(prompt_parts)


# Instância global
scanner = RepoScanner()
