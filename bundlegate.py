#!/usr/bin/env python3
"""
bundlegate — control de salida para paquetes de diagnóstico.

Toma el support bundle que un cliente debe enviarle al fabricante de su software,
produce una COPIA saneada y un MANIFIESTO FIRMADO de lo que se hizo, y bloquea la
salida mientras queden archivos no inspeccionables o hallazgos sin resolver.

Lo que NO promete: "este paquete ya no contiene secretos".
Lo que SÍ promete: "este paquete fue procesado por la política X versión Y, con
estas transformaciones y estas limitaciones comprobables".

Invariantes (verificados en tests):
  1. Nunca modifica el bundle original.
  2. Cero red. Cero credenciales. Cero subprocesos.
  3. El manifiesto NUNCA contiene el valor de un secreto (solo clase, ubicación
     y huella salada e irreversible).
  4. El sobre firmado se valida con LISTA BLANCA CERRADA en todos los niveles:
     un campo extra invalida la firma.

Uso:
    bundlegate.py keygen  --out claves/
    bundlegate.py scan    <bundle.tar.gz|dir> --profile perfiles/generic.json \
                          --out salida/ [--sign claves/private.pem]
    bundlegate.py verify  <salida/manifest.json> [--public-key claves/public.pem]
    bundlegate.py bench   <bundle-con-canarios> --canaries canarios.json
"""

import argparse
import base64
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import shutil
import sys
import tarfile
import tempfile
import zipfile
from collections import Counter, OrderedDict
from datetime import datetime, timezone

TOOL_NAME = "bundlegate"
TOOL_VERSION = "0.1.0"
RULES_VERSION = "2026.08.1"
MANIFEST_FORMAT = "1.0"

# ─────────────────────────────────────────────────────────────────────────────
# Límites de desempaquetado defensivo
# ─────────────────────────────────────────────────────────────────────────────
MAX_ARCHIVE_BYTES = 2 * 1024 ** 3       # 2 GB comprimido
MAX_EXPANDED_BYTES = 10 * 1024 ** 3     # 10 GB expandido
MAX_MEMBER_BYTES = 512 * 1024 ** 2      # 512 MB por archivo
MAX_MEMBERS = 200_000
MAX_COMPRESSION_RATIO = 200             # anti bomba de descompresión
MAX_LINE_BYTES = 64 * 1024              # una línea más larga se trunca al analizar

# Extensiones que sabemos inspeccionar como texto.
INSPECTABLE_EXT = {
    ".log", ".txt", ".json", ".yaml", ".yml", ".csv", ".tsv", ".conf", ".cfg",
    ".ini", ".properties", ".env", ".xml", ".md", ".sh", ".sql", ".toml",
    ".list", ".out", ".err", ".status", ".info", ".trace",
}
# Sin extensión pero nombres típicos de texto en bundles.
INSPECTABLE_NAMES = {
    "dockerfile", "makefile", "hosts", "resolv.conf", "environment",
    "cmdline", "version", "uptime", "meminfo", "cpuinfo",
}
# Extensiones que se bloquean SIEMPRE: no se pueden inspeccionar con garantías.
UNINSPECTABLE_EXT = {
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".pcap", ".pcapng", ".dmp", ".core", ".hprof", ".db", ".sqlite", ".sqlite3",
    ".bin", ".so", ".dylib", ".dll", ".exe", ".class", ".jar", ".war", ".pyc",
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".tgz",
    ".p12", ".pfx", ".jks", ".keystore", ".kdbx",
    ".xlsx", ".docx", ".pptx", ".odt", ".ods",
}

SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW = "critical", "high", "medium", "low"
SEV_ORDER = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_LOW: 3}

ACT_PSEUDONYMIZE = "pseudonymized"   # reemplazado por token estable
ACT_REVIEW = "flagged_for_review"    # ambiguo: decide una persona
ACT_BLOCKED = "blocked"              # el archivo entero no sale


# ─────────────────────────────────────────────────────────────────────────────
# Detectores deterministas.
#   group: si es None se enmascara el match completo; si es int, ese grupo.
# ─────────────────────────────────────────────────────────────────────────────
class Detector(object):
    def __init__(self, cls, pattern, severity, group=None, validator=None):
        self.cls = cls
        self.rx = re.compile(pattern)
        self.severity = severity
        self.group = group
        self.validator = validator


def _luhn_free(_):
    return True


DETECTORS = [
    Detector("private_key_pem",
             r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
             r"[\s\S]{0,8000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
             SEV_CRITICAL),
    Detector("aws_access_key_id", r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b",
             SEV_CRITICAL, group=1),
    Detector("aws_secret_access_key",
             r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
             SEV_CRITICAL, group=1),
    Detector("github_token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", SEV_CRITICAL, group=1),
    Detector("github_pat_fine", r"\b(github_pat_[A-Za-z0-9_]{50,255})\b", SEV_CRITICAL, group=1),
    Detector("slack_token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b", SEV_CRITICAL, group=1),
    Detector("gitlab_token", r"\b(glpat-[A-Za-z0-9_\-]{20,})\b", SEV_CRITICAL, group=1),
    Detector("openai_key", r"\b(sk-[A-Za-z0-9_\-]{20,})\b", SEV_CRITICAL, group=1),
    Detector("google_api_key", r"\b(AIza[0-9A-Za-z_\-]{35})\b", SEV_CRITICAL, group=1),
    Detector("stripe_key", r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b", SEV_CRITICAL, group=1),
    Detector("jwt", r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b",
             SEV_CRITICAL, group=1),
    Detector("connection_string_with_password",
             r"\b[a-z][a-z0-9+.\-]{2,20}://[^\s:@/]{1,64}:([^\s@/]{1,128})@[^\s/]{1,255}",
             SEV_CRITICAL, group=1),
    Detector("bearer_token", r"(?i)\b(?:authorization|proxy-authorization)\s*[:=]\s*"
                             r"[\"']?bearer\s+([A-Za-z0-9._\-+/=]{16,})",
             SEV_CRITICAL, group=1),
    Detector("basic_auth_header",
             r"(?i)\bauthorization\s*[:=]\s*[\"']?basic\s+([A-Za-z0-9+/=]{12,})",
             SEV_CRITICAL, group=1),
    # Sin \b inicial a propósito: `crm_api_key` o `db_password` tienen que matchear.
    # El guion bajo es un carácter de palabra, así que \b se lo comía.
    Detector("password_assignment",
             r"(?i)[A-Za-z0-9_.\-]{0,32}"
             r"(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|"
             r"auth[_\-]?token|client[_\-]?secret|private[_\-]?key)"
             r"[A-Za-z0-9_.\-]{0,16}"
             r"\s*[:=]\s*[\"']?([^\s\"',;{}]{6,256})[\"']?",
             SEV_HIGH, group=1),
    Detector("email", r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24})\b",
             SEV_MEDIUM, group=1),
    Detector("ipv4", r"\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                     r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b",
             SEV_MEDIUM, group=1),
    Detector("home_path", r"((?:/home/|/Users/|C:\\Users\\)[A-Za-z0-9._\-]{1,64})",
             SEV_LOW, group=1),
]

# Placeholders que NO son secretos reales: evitan falsos positivos ruidosos.
PLACEHOLDER_RX = re.compile(
    r"^(?:\*+|x+|X+|<[^>]*>|\{\{?[^}]*\}?\}|\[[^\]]*\]|REDACTED|REDACTADO|null|none|"
    r"true|false|changeme|example|password|secret|your[_\-]?\w*|xxx+|\.\.\.|"
    r"\$\{?\w+\}?|%\w+%|-+|_+|N/?A)$",
    re.I)
# IPs no informativas.
IP_NOISE = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "8.8.8.8", "1.1.1.1"}
# Dominios de ejemplo reservados (RFC 2606): no son PII de nadie.
EMAIL_NOISE_DOMAINS = {"example.com", "example.org", "example.net", "localhost", "test"}

HIGH_ENTROPY_RX = re.compile(r"\b([A-Za-z0-9+/=_\-]{32,128})\b")


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = float(len(s))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def is_placeholder(value):
    v = value.strip().strip("\"'")
    return (not v) or bool(PLACEHOLDER_RX.match(v))


# ─────────────────────────────────────────────────────────────────────────────
# Pseudonimización estable dentro del bundle, irreversible fuera de él.
# ─────────────────────────────────────────────────────────────────────────────
class Pseudonymizer(object):
    """HMAC con sal EFÍMERA (nunca se persiste).

    Mismo valor -> mismo token dentro de un bundle: preserva la correlación
    diagnóstica ("este usuario aparece en 4 archivos") sin revelar el valor.
    Distinta ejecución -> distinta sal: no se pueden cruzar dos bundles ni
    revertir por diccionario.
    """

    def __init__(self):
        self._salt = secrets.token_bytes(32)
        self._seen = {}

    def token(self, cls, value):
        key = (cls, value)
        if key not in self._seen:
            digest = hmac.new(self._salt, (cls + "\x00" + value).encode("utf-8"),
                              hashlib.sha256).hexdigest()[:12]
            self._seen[key] = "<%s:%s>" % (cls.upper(), digest)
        return self._seen[key]

    def fingerprint(self, cls, value):
        """Huella para el manifiesto. Salada => no permite fuerza bruta offline."""
        return hmac.new(self._salt, (cls + "\x00" + value).encode("utf-8"),
                        hashlib.sha256).hexdigest()[:16]

    @property
    def distinct_values(self):
        return len(self._seen)


# ─────────────────────────────────────────────────────────────────────────────
# Perfil (declarativo, NO Turing-completo)
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_PROFILE = OrderedDict([
    ("name", "generic"),
    ("version", "0.1.0"),
    ("description", "Perfil genérico. Un perfil real se calibra por línea de producto."),
    ("deny_files", ["*.p12", "*.pfx", "*.jks", "*.keystore", "id_rsa", "id_ed25519"]),
    ("allow_extra_text_ext", []),
    ("extra_terms", []),          # nombres internos, clientes, plantas: pseudonimizar
    ("severity_policy", OrderedDict([
        (SEV_CRITICAL, ACT_PSEUDONYMIZE),
        (SEV_HIGH, ACT_PSEUDONYMIZE),
        (SEV_MEDIUM, ACT_PSEUDONYMIZE),
        (SEV_LOW, ACT_REVIEW),
    ])),
    ("entropy_min_bits", 4.2),
    ("block_uninspectable", True),
])


def load_profile(path):
    if path is None:
        return json.loads(json.dumps(DEFAULT_PROFILE))
    with open(path, "r", encoding="utf-8") as fh:
        prof = json.load(fh)
    merged = json.loads(json.dumps(DEFAULT_PROFILE))
    for k, v in prof.items():
        if k not in merged:
            raise ValueError("El perfil tiene una clave desconocida: %r. "
                             "El perfil es una lista blanca cerrada." % k)
        merged[k] = v
    return merged


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Extracción defensiva
# ─────────────────────────────────────────────────────────────────────────────
class UnsafeArchive(Exception):
    pass


def _safe_relpath(name):
    """Rechaza rutas absolutas, traversal y separadores raros."""
    if not name or name.startswith("/") or name.startswith("\\"):
        raise UnsafeArchive("ruta absoluta en el archivo: %r" % name)
    if re.match(r"^[A-Za-z]:[\\/]", name):
        raise UnsafeArchive("ruta con unidad de Windows: %r" % name)
    parts = re.split(r"[\\/]+", name)
    if any(p == ".." for p in parts):
        raise UnsafeArchive("path traversal en el archivo: %r" % name)
    return os.path.join(*[p for p in parts if p not in ("", ".")]) if parts else name


def extract_tar(src, dest):
    total = 0
    count = 0
    comp_size = os.path.getsize(src)
    with tarfile.open(src, "r:*") as tf:
        for m in tf:
            count += 1
            if count > MAX_MEMBERS:
                raise UnsafeArchive("demasiados miembros (>%d)" % MAX_MEMBERS)
            if m.issym() or m.islnk():
                raise UnsafeArchive("enlace simbólico o duro en el archivo: %r" % m.name)
            if m.isdev() or m.isfifo():
                raise UnsafeArchive("nodo especial en el archivo: %r" % m.name)
            if not (m.isfile() or m.isdir()):
                continue
            rel = _safe_relpath(m.name)
            if m.isdir():
                os.makedirs(os.path.join(dest, rel), exist_ok=True)
                continue
            if m.size > MAX_MEMBER_BYTES:
                raise UnsafeArchive("miembro demasiado grande: %r" % m.name)
            total += m.size
            if total > MAX_EXPANDED_BYTES:
                raise UnsafeArchive("expansión total excede el límite")
            if comp_size > 0 and total / float(comp_size) > MAX_COMPRESSION_RATIO:
                raise UnsafeArchive("ratio de compresión sospechoso (posible bomba)")
            out = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            fsrc = tf.extractfile(m)
            if fsrc is None:
                continue
            with open(out, "wb") as fdst:
                shutil.copyfileobj(fsrc, fdst, 1024 * 1024)
    return total


def extract_zip(src, dest):
    total = 0
    comp_size = os.path.getsize(src)
    with zipfile.ZipFile(src) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise UnsafeArchive("demasiados miembros (>%d)" % MAX_MEMBERS)
        for info in infos:
            if info.is_dir():
                os.makedirs(os.path.join(dest, _safe_relpath(info.filename)), exist_ok=True)
                continue
            # bit 0xA000 en los 16 bits altos de external_attr => symlink
            if (info.external_attr >> 16) & 0xA000 == 0xA000:
                raise UnsafeArchive("enlace simbólico en el zip: %r" % info.filename)
            if info.file_size > MAX_MEMBER_BYTES:
                raise UnsafeArchive("miembro demasiado grande: %r" % info.filename)
            total += info.file_size
            if total > MAX_EXPANDED_BYTES:
                raise UnsafeArchive("expansión total excede el límite")
            if comp_size > 0 and total / float(comp_size) > MAX_COMPRESSION_RATIO:
                raise UnsafeArchive("ratio de compresión sospechoso (posible bomba)")
            rel = _safe_relpath(info.filename)
            out = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with zf.open(info) as fsrc, open(out, "wb") as fdst:
                shutil.copyfileobj(fsrc, fdst, 1024 * 1024)
    return total


def materialize(src, workdir):
    """Devuelve (raíz_del_contenido, modo). NUNCA toca el original."""
    root = os.path.join(workdir, "input")
    os.makedirs(root, exist_ok=True)
    if os.path.isdir(src):
        shutil.copytree(src, os.path.join(root, os.path.basename(os.path.abspath(src))),
                        symlinks=False, ignore_dangling_symlinks=True)
        return root, "directory"
    size = os.path.getsize(src)
    if size > MAX_ARCHIVE_BYTES:
        raise UnsafeArchive("el archivo comprimido supera el límite de entrada")
    if tarfile.is_tarfile(src):
        extract_tar(src, root)
        return root, "tar"
    if zipfile.is_zipfile(src):
        extract_zip(src, root)
        return root, "zip"
    raise UnsafeArchive("formato de entrada no reconocido (se espera tar, tar.gz, tgz o zip)")


# ─────────────────────────────────────────────────────────────────────────────
# Clasificación de archivos
# ─────────────────────────────────────────────────────────────────────────────
def looks_binary(path, probe=8192):
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(probe)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    printable = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126 or b >= 128)
    return (printable / float(len(chunk))) < 0.85


def fnmatch_any(name, patterns):
    import fnmatch
    base = os.path.basename(name)
    return any(fnmatch.fnmatch(base, p) or fnmatch.fnmatch(name, p) for p in patterns)


def classify(relpath, abspath, profile):
    """Devuelve ('inspect'|'block', motivo)."""
    if fnmatch_any(relpath, profile["deny_files"]):
        return "block", "denegado por el perfil"
    ext = os.path.splitext(relpath)[1].lower()
    if ext in UNINSPECTABLE_EXT:
        return "block", "formato no inspeccionable (%s)" % (ext or "sin extensión")
    allowed = set(INSPECTABLE_EXT) | set(profile.get("allow_extra_text_ext") or [])
    if ext in allowed or os.path.basename(relpath).lower() in INSPECTABLE_NAMES or ext == "":
        if looks_binary(abspath):
            return "block", "contenido binario"
        return "inspect", "texto"
    if looks_binary(abspath):
        return "block", "contenido binario"
    return "inspect", "texto sin extensión conocida"


# ─────────────────────────────────────────────────────────────────────────────
# Escaneo y saneado de una línea
# ─────────────────────────────────────────────────────────────────────────────
class Finding(object):
    __slots__ = ("cls", "path", "line", "severity", "action", "fingerprint")

    def __init__(self, cls, path, line, severity, action, fingerprint):
        self.cls, self.path, self.line = cls, path, line
        self.severity, self.action, self.fingerprint = severity, action, fingerprint

    def as_dict(self):
        return OrderedDict([
            ("class", self.cls), ("file", self.path), ("line", self.line),
            ("severity", self.severity), ("action", self.action),
            ("fingerprint", self.fingerprint),
        ])


def _noise(cls, value):
    if is_placeholder(value):
        return True
    if cls == "ipv4" and value in IP_NOISE:
        return True
    if cls == "email":
        dom = value.rsplit("@", 1)[-1].lower()
        if dom in EMAIL_NOISE_DOMAINS or dom.endswith(".example.com"):
            return True
    if cls == "password_assignment" and len(value.strip("\"'")) < 6:
        return True
    return False


def _line_index(text):
    """Offsets donde empieza cada línea, para traducir posición -> nº de línea."""
    starts = [0]
    for m in re.finditer(r"\n", text):
        starts.append(m.end())
    return starts


def scan_text(text, relpath, profile, pseudo, extra_terms_rx):
    """Devuelve (texto_saneado, [Finding]).

    El escaneo va sobre el texto COMPLETO, no línea por línea: si no, un bloque
    PEM —que ocupa varias líneas— nunca matchearía. Ese fallo existió en la
    primera versión y lo destapó el banco de canarios.
    """
    findings = []
    policy = profile["severity_policy"]
    if len(text) > MAX_MEMBER_BYTES:
        text_head, text_tail = text[:MAX_MEMBER_BYTES], text[MAX_MEMBER_BYTES:]
    else:
        text_head, text_tail = text, ""

    spans = []  # (inicio, fin, reemplazo, cls, severidad, accion, huella)

    for det in DETECTORS:
        for m in det.rx.finditer(text_head):
            gi = det.group
            value = m.group(gi) if gi else m.group(0)
            if not value or _noise(det.cls, value):
                continue
            action = policy.get(det.severity, ACT_REVIEW)
            start, end = (m.span(gi) if gi else m.span(0))
            fp = pseudo.fingerprint(det.cls, value)
            repl = pseudo.token(det.cls, value) if action == ACT_PSEUDONYMIZE else None
            spans.append((start, end, repl, det.cls, det.severity, action, fp))

    if extra_terms_rx is not None:
        for m in extra_terms_rx.finditer(text_head):
            value = m.group(0)
            fp = pseudo.fingerprint("profile_term", value)
            spans.append((m.start(), m.end(), pseudo.token("term", value),
                          "profile_term", SEV_HIGH, ACT_PSEUDONYMIZE, fp))

    # Entropía: red de seguridad, solo sobre lo que ningún detector exacto reclamó.
    claimed = [(s, e) for s, e, _, _, _, _, _ in spans]
    claimed.sort()
    for m in HIGH_ENTROPY_RX.finditer(text_head):
        s, e = m.span(1)
        if any(s < ce and cs < e for cs, ce in claimed):
            continue
        val = m.group(1)
        if is_placeholder(val) or val.isdigit() or val.isalpha():
            continue
        if shannon_entropy(val) < profile["entropy_min_bits"]:
            continue
        spans.append((s, e, None, "high_entropy_string", SEV_MEDIUM,
                      ACT_REVIEW, pseudo.fingerprint("high_entropy_string", val)))

    if not spans:
        return text, findings

    # Solapamientos: gana el más severo; a igual severidad, el más largo.
    spans.sort(key=lambda t: (SEV_ORDER[t[4]], -(t[1] - t[0]), t[0]))
    chosen = []
    for sp in spans:
        if any(sp[0] < c[1] and c[0] < sp[1] for c in chosen):
            continue
        chosen.append(sp)
    chosen.sort(key=lambda t: t[0])

    import bisect
    starts = _line_index(text_head)
    rebuilt, cursor = [], 0
    for start, end, repl, cls, sev, action, fp in chosen:
        lineno = bisect.bisect_right(starts, start)
        findings.append(Finding(cls, relpath, lineno, sev, action, fp))
        rebuilt.append(text_head[cursor:start])
        rebuilt.append(repl if repl is not None else text_head[start:end])
        cursor = end
    rebuilt.append(text_head[cursor:])
    rebuilt.append(text_tail)
    return "".join(rebuilt), findings


# ─────────────────────────────────────────────────────────────────────────────
# Firma / verificación
# ─────────────────────────────────────────────────────────────────────────────
def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def keygen(outdir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    os.makedirs(outdir, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    priv_path = os.path.join(outdir, "private.pem")
    pub_path = os.path.join(outdir, "public.pem")
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with open(pub_path, "wb") as fh:
        fh.write(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv_path, pub_path


def sign_envelope(manifest, priv_pem_path):
    from cryptography.hazmat.primitives import serialization
    with open(priv_pem_path, "rb") as fh:
        priv = serialization.load_pem_private_key(fh.read(), password=None)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = priv.sign(_canonical(manifest))
    return OrderedDict([
        ("manifest", manifest),
        ("signature", OrderedDict([
            ("algorithm", "Ed25519"),
            ("public_key_raw_b64", base64.b64encode(pub_raw).decode()),
            ("value_b64", base64.b64encode(sig).decode()),
        ])),
    ])


# LISTA BLANCA CERRADA — un campo extra en CUALQUIER nivel invalida el sobre.
ENVELOPE_SCHEMA = {
    "__keys__": {"manifest", "signature"},
    "signature": {"__keys__": {"algorithm", "public_key_raw_b64", "value_b64"}},
    "manifest": {
        "__keys__": {
            "manifest_format", "tool", "generated_utc", "input", "output", "profile",
            "rules_version", "inventory", "coverage", "findings", "blocked_files",
            "limitations", "status",
        },
        "tool": {"__keys__": {"name", "version"}},
        "input": {"__keys__": {"name", "sha256", "bytes", "mode"}},
        "output": {"__keys__": {"name", "sha256", "bytes"}},
        "profile": {"__keys__": {"name", "version", "sha256"}},
        "inventory": {"__keys__": {"files_total", "inspected", "blocked", "empty"}},
        "coverage": {"__keys__": {"bytes_inspected", "bytes_not_inspected", "percent_inspected"}},
        "findings": {"__item__": {"__keys__": {"class", "file", "line", "severity",
                                               "action", "fingerprint"}}},
        "blocked_files": {"__item__": {"__keys__": {"file", "reason", "bytes"}}},
    },
}


def validate_closed(obj, schema, path="$"):
    """Rechaza cualquier clave no declarada, en todos los niveles."""
    errors = []
    if "__keys__" in schema:
        if not isinstance(obj, dict):
            return ["%s: se esperaba un objeto" % path]
        allowed = schema["__keys__"]
        extra = set(obj.keys()) - allowed
        missing = allowed - set(obj.keys())
        for k in sorted(extra):
            errors.append("%s.%s: campo NO DECLARADO (lista blanca cerrada)" % (path, k))
        for k in sorted(missing):
            errors.append("%s.%s: campo obligatorio ausente" % (path, k))
        for k, sub in schema.items():
            if k == "__keys__" or k not in obj:
                continue
            errors.extend(validate_closed(obj[k], sub, "%s.%s" % (path, k)))
    if "__item__" in schema:
        if not isinstance(obj, list):
            return errors + ["%s: se esperaba una lista" % path]
        for i, item in enumerate(obj):
            errors.extend(validate_closed(item, schema["__item__"], "%s[%d]" % (path, i)))
    return errors


def verify_envelope(env, public_pem_path=None):
    """Devuelve (codigo_salida, lineas). 0=probada  2=inválida  3=no probada."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    out = []
    errs = validate_closed(env, ENVELOPE_SCHEMA)
    if errs:
        out.append("ESTRUCTURA INVÁLIDA — el sobre no supera la lista blanca cerrada:")
        out.extend("   · " + e for e in errs)
        return 2, out

    sig = base64.b64decode(env["signature"]["value_b64"])
    if env["signature"]["algorithm"] != "Ed25519":
        return 2, ["Algoritmo de firma no admitido: %r" % env["signature"]["algorithm"]]

    external = public_pem_path is not None
    if external:
        with open(public_pem_path, "rb") as fh:
            pub = serialization.load_pem_public_key(fh.read())
    else:
        pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(env["signature"]["public_key_raw_b64"]))

    try:
        pub.verify(sig, _canonical(env["manifest"]))
    except InvalidSignature:
        return 2, ["FIRMA INVÁLIDA — el manifiesto fue alterado o la clave no corresponde."]

    if external:
        out.append("VERIFICADA — firma válida contra la clave pública que aportaste.")
        out.append("La procedencia queda probada respecto de esa clave.")
        return 0, out

    out.append("NO PROBADA — la firma es coherente con la clave que viaja DENTRO del")
    out.append("propio archivo. Eso demuestra integridad interna, NO procedencia:")
    out.append("cualquiera pudo firmar con su propia clave. Volvé a verificar con")
    out.append("--public-key <clave obtenida por un canal independiente>.")
    return 3, out


# ─────────────────────────────────────────────────────────────────────────────
# Comando: scan
# ─────────────────────────────────────────────────────────────────────────────
def build_terms_rx(terms):
    terms = [t for t in (terms or []) if t and len(t) >= 3]
    if not terms:
        return None
    terms.sort(key=len, reverse=True)
    return re.compile(r"(?<![A-Za-z0-9_])(?:%s)(?![A-Za-z0-9_])"
                      % "|".join(re.escape(t) for t in terms), re.I)


def cmd_scan(args):
    src = os.path.abspath(args.bundle)
    if not os.path.exists(src):
        die("No existe la entrada: %s" % src)
    profile = load_profile(args.profile)
    profile_sha = sha256_bytes(_canonical(profile))
    pseudo = Pseudonymizer()
    terms_rx = build_terms_rx(profile.get("extra_terms"))

    outdir = os.path.abspath(args.out)
    os.makedirs(outdir, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix="bundlegate-")
    sanitized_root = os.path.join(workdir, "sanitized")
    os.makedirs(sanitized_root, exist_ok=True)

    findings, blocked = [], []
    n_files = n_inspected = n_empty = 0
    bytes_inspected = bytes_blocked = 0

    try:
        root, mode = materialize(src, workdir)

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if not os.path.islink(os.path.join(dirpath, d))]
            for fn in sorted(filenames):
                abspath = os.path.join(dirpath, fn)
                if os.path.islink(abspath):
                    continue
                rel = os.path.relpath(abspath, root)
                n_files += 1
                size = os.path.getsize(abspath)
                if size == 0:
                    n_empty += 1
                    _copy_into(sanitized_root, rel, b"")
                    continue

                verdict, reason = classify(rel, abspath, profile)
                if verdict == "block" and profile["block_uninspectable"]:
                    blocked.append(OrderedDict([("file", rel), ("reason", reason),
                                                ("bytes", size)]))
                    bytes_blocked += size
                    continue

                with open(abspath, "rb") as fh:
                    raw = fh.read()
                text = raw.decode("utf-8", errors="replace")
                clean, f = scan_text(text, rel, profile, pseudo, terms_rx)
                findings.extend(f)
                n_inspected += 1
                bytes_inspected += size
                _copy_into(sanitized_root, rel, clean.encode("utf-8"))

        out_name = args.output_name or (_base_no_ext(src) + ".sanitized.tar.gz")
        out_path = os.path.join(outdir, out_name)
        _pack(sanitized_root, out_path)

        total_bytes = bytes_inspected + bytes_blocked
        pct = (100.0 * bytes_inspected / total_bytes) if total_bytes else 100.0
        needs_review = [f for f in findings if f.action == ACT_REVIEW]
        status = "BLOCKED" if blocked else ("REVIEW" if needs_review else "PASS")

        limitations = [
            "La detección es best-effort: NO se garantiza haber encontrado toda la "
            "información sensible.",
            "Solo se inspecciona contenido de texto; los formatos no inspeccionables "
            "se bloquean enteros, no se depuran.",
            "Los pseudónimos son estables dentro de este paquete y no se pueden cruzar "
            "con otro paquete (la sal es efímera y no se guarda).",
            "Este manifiesto describe un proceso aplicado, no certifica ausencia de "
            "datos sensibles ni conformidad con ninguna norma.",
        ]
        if any(f.cls == "high_entropy_string" for f in needs_review):
            limitations.append("Hay cadenas de alta entropía sin clasificar: requieren "
                               "decisión humana.")

        manifest = OrderedDict([
            ("manifest_format", MANIFEST_FORMAT),
            ("tool", OrderedDict([("name", TOOL_NAME), ("version", TOOL_VERSION)])),
            ("generated_utc", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
            ("input", OrderedDict([("name", os.path.basename(src)),
                                   ("sha256", sha256_file(src) if os.path.isfile(src) else ""),
                                   ("bytes", os.path.getsize(src) if os.path.isfile(src) else 0),
                                   ("mode", mode)])),
            ("output", OrderedDict([("name", os.path.basename(out_path)),
                                    ("sha256", sha256_file(out_path)),
                                    ("bytes", os.path.getsize(out_path))])),
            ("profile", OrderedDict([("name", profile["name"]),
                                     ("version", profile["version"]),
                                     ("sha256", profile_sha)])),
            ("rules_version", RULES_VERSION),
            ("inventory", OrderedDict([("files_total", n_files), ("inspected", n_inspected),
                                       ("blocked", len(blocked)), ("empty", n_empty)])),
            ("coverage", OrderedDict([("bytes_inspected", bytes_inspected),
                                      ("bytes_not_inspected", bytes_blocked),
                                      ("percent_inspected", round(pct, 2))])),
            ("findings", [f.as_dict() for f in findings]),
            ("blocked_files", blocked),
            ("limitations", limitations),
            ("status", status),
        ])

        env = (sign_envelope(manifest, args.sign) if args.sign
               else OrderedDict([("manifest", manifest),
                                 ("signature", OrderedDict([("algorithm", "none"),
                                                            ("public_key_raw_b64", ""),
                                                            ("value_b64", "")]))]))
        man_path = os.path.join(outdir, "manifest.json")
        with open(man_path, "w", encoding="utf-8") as fh:
            json.dump(env, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

        _report(manifest, findings, out_path, man_path, args.sign)
        return {"PASS": 0, "REVIEW": 3, "BLOCKED": 4}[status]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _base_no_ext(p):
    b = os.path.basename(p.rstrip("/"))
    for suf in (".tar.gz", ".tgz", ".tar", ".zip"):
        if b.lower().endswith(suf):
            return b[: -len(suf)]
    return b


def _copy_into(root, rel, data):
    dst = os.path.join(root, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as fh:
        fh.write(data)


def _pack(root, out_path):
    with tarfile.open(out_path, "w:gz") as tf:
        for dirpath, _dirs, files in os.walk(root):
            for fn in sorted(files):
                full = os.path.join(dirpath, fn)
                tf.add(full, arcname=os.path.relpath(full, root))


def _report(manifest, findings, out_path, man_path, signed):
    by_class = Counter(f.cls for f in findings)
    by_sev = Counter(f.severity for f in findings)
    st = manifest["status"]
    icon = {"PASS": "PASA", "REVIEW": "REVISAR", "BLOCKED": "BLOQUEADO"}[st]
    print("")
    print("  bundlegate %s — %s" % (TOOL_VERSION, manifest["profile"]["name"]))
    print("  " + "─" * 66)
    print("  Estado                 %s" % icon)
    print("  Archivos               %d totales · %d inspeccionados · %d bloqueados · %d vacíos"
          % (manifest["inventory"]["files_total"], manifest["inventory"]["inspected"],
             manifest["inventory"]["blocked"], manifest["inventory"]["empty"]))
    print("  Cobertura              %.2f%% de los bytes inspeccionados"
          % manifest["coverage"]["percent_inspected"])
    print("  Hallazgos              %d  (críticos %d · altos %d · medios %d · bajos %d)"
          % (len(findings), by_sev[SEV_CRITICAL], by_sev[SEV_HIGH],
             by_sev[SEV_MEDIUM], by_sev[SEV_LOW]))
    if by_class:
        print("  " + "─" * 66)
        for cls, n in by_class.most_common(12):
            print("    %-34s %5d" % (cls, n))
    if manifest["blocked_files"]:
        print("  " + "─" * 66)
        print("  Bloqueados (no salen del perímetro):")
        for b in manifest["blocked_files"][:8]:
            print("    · %-44s %s" % (b["file"][:44], b["reason"]))
        if len(manifest["blocked_files"]) > 8:
            print("    … y %d más" % (len(manifest["blocked_files"]) - 8))
    print("  " + "─" * 66)
    print("  Copia saneada          %s" % out_path)
    print("  Manifiesto             %s%s" % (man_path, "" if signed else "  (SIN FIRMAR)"))
    print("")


# ─────────────────────────────────────────────────────────────────────────────
# Comando: bench  (mide recall contra canarios plantados)
# ─────────────────────────────────────────────────────────────────────────────
def cmd_bench(args):
    """Mide qué pasó con cada canario. Cuatro desenlaces, no dos.

    Un banco que solo dice "contenido / no contenido" miente por omisión: un
    valor puede seguir presente en la copia y estar igualmente contenido porque
    su archivo se bloqueó, o porque quedó marcado para revisión humana. Y al
    revés: la primera versión de este comando comparaba cada canario contra
    CADA archivo y lo daba por contenido en cuanto no aparecía en uno
    cualquiera — informaba 100% sin haber medido nada.
    """
    with open(args.canaries, "r", encoding="utf-8") as fh:
        ledger = json.load(fh)
    profile = load_profile(args.profile)
    pseudo = Pseudonymizer()
    terms_rx = build_terms_rx(profile.get("extra_terms"))

    root = os.path.abspath(args.bundle)
    workdir = tempfile.mkdtemp(prefix="bundlegate-bench-")
    sanitized_all = []          # texto que SÍ sale del perímetro
    blocked_rel = set()
    flagged_at = set()          # (archivo, línea) marcados para revisión
    total_lines = 0
    try:
        content_root, _mode = materialize(root, workdir)
        for dirpath, _d, files in os.walk(content_root):
            for fn in sorted(files):
                abspath = os.path.join(dirpath, fn)
                rel = os.path.relpath(abspath, content_root)
                verdict, _r = classify(rel, abspath, profile)
                if verdict == "block":
                    blocked_rel.add(rel.replace(os.sep, "/"))
                    continue
                with open(abspath, "rb") as fh:
                    text = fh.read().decode("utf-8", errors="replace")
                total_lines += text.count("\n")
                clean, fs = scan_text(text, rel, profile, pseudo, terms_rx)
                sanitized_all.append(clean)
                for f in fs:
                    if f.action == ACT_REVIEW:
                        flagged_at.add((rel.replace(os.sep, "/"), f.line))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    outgoing = "\n".join(sanitized_all)

    NEUTRALIZED, RETAINED, FLAGGED, ESCAPED = ("neutralizado", "retenido en el perímetro",
                                               "marcado para revisión", "ESCAPADO")
    results = []
    for c in ledger["canaries"]:
        cfile = c["file"].replace(os.sep, "/")
        if cfile in blocked_rel:
            outcome = RETAINED
        elif c["value"] not in outgoing:
            outcome = NEUTRALIZED
        elif (cfile, c.get("line")) in flagged_at:
            outcome = FLAGGED
        else:
            outcome = ESCAPED
        results.append((c, outcome))

    by_class = OrderedDict()
    for c, outcome in results:
        d = by_class.setdefault(c["class"], Counter())
        d[outcome] += 1

    counts = Counter(o for _c, o in results)
    n = len(results)
    contained = counts[NEUTRALIZED] + counts[RETAINED] + counts[FLAGGED]
    escaped = counts[ESCAPED]

    print("")
    print("  Banco de pruebas — qué pasó con cada canario plantado")
    print("  " + "─" * 70)
    print("    %-30s %8s %8s %8s %8s" % ("CLASE", "NEUTR.", "RETEN.", "MARCADO", "ESCAPA"))
    for cls in sorted(by_class):
        d = by_class[cls]
        flag = "" if d[ESCAPED] == 0 else "   <-- FALLA"
        print("    %-30s %8d %8d %8d %8d%s"
              % (cls, d[NEUTRALIZED], d[RETAINED], d[FLAGGED], d[ESCAPED], flag))
    print("  " + "─" * 70)
    print("    %-30s %8d %8d %8d %8d" % ("TOTAL (%d)" % n, counts[NEUTRALIZED],
                                         counts[RETAINED], counts[FLAGGED], counts[ESCAPED]))
    print("")
    print("  Contenidos            %d de %d  (%.1f%%)" % (contained, n, 100.0 * contained / n))
    print("  Escapados             %d        <- el único número que importa" % escaped)
    print("  Líneas analizadas     %d" % total_lines)
    print("")
    print("  Lectura: NEUTRALIZADO = reemplazado por un pseudónimo · RETENIDO = su archivo")
    print("  se bloqueó entero · MARCADO = sigue en la copia pero una persona tiene que")
    print("  decidir, y el paquete no sale hasta que lo haga · ESCAPADO = salió sin que")
    print("  nadie lo señalara. Solo esto último es un fallo.")
    print("")
    if escaped:
        print("  ESCAPADOS (esto es lo que hay que mostrarle al comprador, sin maquillar):")
        for c, o in results:
            if o == ESCAPED:
                print("    · %-26s %s:%s" % (c["class"], c["file"], c.get("line", "?")))
        print("")
    return 1 if escaped else 0


# ─────────────────────────────────────────────────────────────────────────────
def die(msg, code=2):
    sys.stderr.write("bundlegate: %s\n" % msg)
    raise SystemExit(code)


def main(argv=None):
    p = argparse.ArgumentParser(prog="bundlegate", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="sanea un paquete y emite el manifiesto")
    s.add_argument("bundle")
    s.add_argument("--profile", default=None)
    s.add_argument("--out", default="salida")
    s.add_argument("--output-name", default=None)
    s.add_argument("--sign", default=None, metavar="private.pem")

    v = sub.add_parser("verify", help="verifica un manifiesto firmado")
    v.add_argument("manifest")
    v.add_argument("--public-key", default=None)

    k = sub.add_parser("keygen", help="genera un par Ed25519")
    k.add_argument("--out", default="claves")

    b = sub.add_parser("bench", help="mide recall contra canarios plantados")
    b.add_argument("bundle")
    b.add_argument("--canaries", required=True)
    b.add_argument("--profile", default=None)

    args = p.parse_args(argv)
    if not args.cmd:
        p.print_help()
        return 2

    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "bench":
        return cmd_bench(args)
    if args.cmd == "keygen":
        priv, pub = keygen(args.out)
        print("Clave privada  %s  (modo 0600)" % priv)
        print("Clave pública  %s" % pub)
        return 0
    if args.cmd == "verify":
        with open(args.manifest, "r", encoding="utf-8") as fh:
            env = json.load(fh)
        code, lines = verify_envelope(env, args.public_key)
        print("")
        for ln in lines:
            print("  " + ln)
        print("")
        return code
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
