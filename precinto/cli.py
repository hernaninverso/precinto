#!/usr/bin/env python3
"""
precinto — control de salida para paquetes de diagnóstico.

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
    precinto.py keygen  --out claves/
    precinto.py scan    <bundle.tar.gz|dir> --profile perfiles/generic.json \
                          --out salida/ [--sign claves/private.pem]
    precinto.py verify  <salida/manifest.json> [--public-key claves/public.pem]
    precinto.py bench   <bundle-con-canarios> --canaries canarios.json
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

TOOL_NAME = "precinto"
TOOL_VERSION = "0.1.0"   # reserva; la real sale de los metadatos, ver _version()
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
        self.group = group          # int, tupla de alternativas, o None
        self.validator = validator

    def pick(self, m):
        """Devuelve (valor, inicio, fin) del grupo que realmente casó."""
        g = self.group
        if g is None:
            return m.group(0), m.start(0), m.end(0)
        if isinstance(g, tuple):
            for gi in g:
                if m.group(gi) is not None:
                    return m.group(gi), m.start(gi), m.end(gi)
            return None, -1, -1
        return m.group(g), m.start(g), m.end(g)


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
    # Entre comillas se acepta el valor CON espacios: `password: "correct horse
    # battery staple"` solo enmascaraba `correct` y el resto de la frase salía
    # entera. Sin comillas se sigue cortando en el primer espacio, que es lo
    # correcto: ahí el espacio separa el valor de lo que viene después.
    Detector("password_assignment",
             r"(?i)[A-Za-z0-9_.\-]{0,32}"
             r"(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|"
             r"auth[_\-]?token|client[_\-]?secret|private[_\-]?key|passphrase|token|credential|bearer)"
             # La palabra clave tiene que TERMINAR el identificador: `db_password=`
             # sí, `token_count=` no. Sin esto se pseudonimizaban
             # `token_count=100000`, `credential_provider=default` y
             # `bearer_strategy=enabled`, destruyendo diagnóstico legítimo.
             r"(?![A-Za-z0-9_])"
             r"\s*[:=]\s*"
             r"(?:\"([^\"\r\n]{6,256})\"|'([^'\r\n]{6,256})'|([^\r\n,;{}]{6,256}))",
             SEV_HIGH, group=(1, 2, 3)),
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

    def review_token(self, cls, value):
        """Marca de revisión: tapa el valor igual que un pseudónimo, pero se
        distingue a simple vista para que una persona sepa qué mirar."""
        return "<REVISAR:%s:%s>" % (cls.upper(), self.fingerprint(cls, value))

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


VALID_SEVERITIES = {SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW}
# Un perfil NO puede pedir que un hallazgo se deje pasar. Sin esta lista, un
# perfil con {"severity_policy":{"critical":"allow"}} dejaba el token intacto y
# el resultado seguía siendo PASS: fail-open silencioso por configuración.
VALID_ACTIONS = {ACT_PSEUDONYMIZE, ACT_REVIEW}


def perfiles_incluidos():
    """Nombres de los perfiles que viajan dentro del paquete."""
    try:
        from importlib.resources import files
        d = files("precinto").joinpath("perfiles")
        return sorted(p.name[:-5] for p in d.iterdir() if p.name.endswith(".json"))
    except Exception:
        d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "perfiles")
        if not os.path.isdir(d):
            return []
        return sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json"))


def _leer_perfil(ref):
    """Acepta una RUTA (compatibilidad con lo ya publicado) o un NOMBRE incluido.

    Se usa `importlib.resources`, nunca `__file__`: la ruta derivada de `__file__`
    funciona en el checkout y falla dentro de una rueda. Es exactamente el fallo
    por el que `eleion-compliance-kit` quedó con todos sus cargadores rotos.
    """
    # isfile, no exists: con `--profile demo` y un directorio `demo/` al lado,
    # `exists` daba True y se intentaba abrir el directorio como archivo.
    if os.path.isfile(ref):
        with open(ref, "r", encoding="utf-8") as fh:
            return json.load(fh)
    nombre = ref[:-5] if ref.endswith(".json") else ref
    try:
        from importlib.resources import files
        recurso = files("precinto").joinpath("perfiles", nombre + ".json")
        if recurso.is_file():
            return json.loads(recurso.read_text(encoding="utf-8"))
    except Exception:
        pass
    disponibles = perfiles_incluidos()
    raise ValueError("No encontré el perfil %r. No es una ruta existente ni uno de los "
                     "incluidos: %s" % (ref, ", ".join(disponibles) or "(ninguno)"))


def load_profile(path):
    if path is None:
        return json.loads(json.dumps(DEFAULT_PROFILE))
    prof = _leer_perfil(path)
    merged = json.loads(json.dumps(DEFAULT_PROFILE))
    for k, v in prof.items():
        if k not in merged:
            raise ValueError("El perfil tiene una clave desconocida: %r. "
                             "El perfil es una lista blanca cerrada." % k)
        merged[k] = v
    _validate_profile(merged)
    return merged


def _validate_profile(p):
    """Valida VALORES, no solo nombres de clave. Todo lo que no se entienda, se rechaza."""
    pol = p.get("severity_policy")
    if not isinstance(pol, dict):
        raise ValueError("severity_policy debe ser un objeto.")
    for k, v in pol.items():
        if k not in VALID_SEVERITIES:
            raise ValueError("severity_policy: severidad desconocida %r (válidas: %s)"
                             % (k, ", ".join(sorted(VALID_SEVERITIES))))
        if v not in VALID_ACTIONS:
            raise ValueError("severity_policy[%r]: acción %r no permitida. Un perfil no "
                             "puede dejar pasar un hallazgo; válidas: %s"
                             % (k, v, ", ".join(sorted(VALID_ACTIONS))))
    for sev in VALID_SEVERITIES:
        if sev not in pol:
            raise ValueError("severity_policy: falta la severidad %r. Debe declararse "
                             "explícitamente qué se hace con cada una." % sev)
    for key in ("deny_files", "allow_extra_text_ext", "extra_terms"):
        v = p.get(key)
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ValueError("%s debe ser una lista de cadenas." % key)
    if not isinstance(p.get("entropy_min_bits"), (int, float)):
        raise ValueError("entropy_min_bits debe ser un número.")
    if p.get("block_uninspectable") is not True:
        raise ValueError("block_uninspectable no puede desactivarse: un archivo que no se "
                         "puede inspeccionar no puede salir. La opción existe solo para que "
                         "el perfil lo declare de forma explícita.")
    for key in ("name", "version", "description"):
        if not isinstance(p.get(key), str):
            raise ValueError("%s debe ser una cadena." % key)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_tree(root):
    """Hash reproducible de un árbol de directorios.

    En modo directorio el manifiesto declaraba `input.sha256 = ""`: se firmaba un
    vacío, y con él la afirmación "esta entrada es la que dice" no valía nada.
    Se hashea la lista ORDENADA de (ruta relativa, tamaño, hash del contenido),
    que es estable entre máquinas y detecta tanto un cambio de contenido como un
    archivo agregado, quitado o renombrado. Los enlaces simbólicos se ignoran,
    igual que en la copia.
    """
    h = hashlib.sha256()
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue
            entries.append((os.path.relpath(full, root).replace(os.sep, "/"),
                            os.path.getsize(full), sha256_file(full)))
    for rel, size, digest in sorted(entries):
        # surrogateescape: un nombre POSIX puede no ser UTF-8 válido y
        # `encode("utf-8")` explotaría con un paquete legítimo.
        h.update(("%s\0%d\0%s\n" % (rel, size, digest))
                 .encode("utf-8", errors="surrogateescape"))
    return h.hexdigest(), sum(e[1] for e in entries)


# ─────────────────────────────────────────────────────────────────────────────
# Extracción defensiva
# ─────────────────────────────────────────────────────────────────────────────
class UnsafeArchive(Exception):
    pass


class TooLargeToInspect(Exception):
    """El contenido excede lo que se puede analizar con garantías -> se bloquea."""

    def __init__(self, size):
        super(TooLargeToInspect, self).__init__("contenido de %d bytes" % size)
        self.size = size


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


def _copy_fd_to(path_dst, fd, limite):
    """Copia desde un descriptor YA abierto y validado. Cuenta los bytes REALES."""
    total = 0
    with open(path_dst, "wb") as out:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limite:
                raise UnsafeArchive("un archivo creció por encima del límite durante la copia")
            out.write(chunk)
    return total


def snapshot_tree(src, dest):
    """Instantánea privada de un directorio, inmune a symlinks y a carreras.

    Tres problemas que esto cierra de una vez:

    - `shutil.copyfile` decide por RUTA antes de abrir, así que entre `islink()` y
      la copia un atacante puede intercambiar el archivo por un enlace y hacer que
      termine leyendo un destino externo (CWE-367). Acá cada archivo se abre con
      `O_NOFOLLOW` **relativo al descriptor del directorio ya validado**, y se
      comprueba con `fstat` sobre ese mismo descriptor.
    - El tamaño se contaba con `getsize()` antes de copiar, así que un archivo que
      crecía después esquivaba los límites. Ahora se cuentan los bytes leídos.
    - Todo lo posterior —hash, escaneo— trabaja SOBRE ESTA COPIA, no sobre el
      original, así que ya no hay ventana entre hashear y procesar.
    """
    import stat as _stat
    total = 0
    count = 0
    src = os.path.abspath(src)

    def recorrer(dir_fd, rel):
        nonlocal total, count
        with os.scandir(dir_fd) as it:
            entradas = sorted(it, key=lambda e: e.name)
        for ent in entradas:
            nombre = ent.name
            if nombre in (".", ".."):
                continue
            try:
                sub_fd = os.open(nombre, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY,
                                 dir_fd=dir_fd)
            except (NotADirectoryError, OSError):
                sub_fd = None
            if sub_fd is not None:
                try:
                    os.makedirs(os.path.join(dest, rel, nombre), exist_ok=True)
                    recorrer(sub_fd, os.path.join(rel, nombre))
                finally:
                    os.close(sub_fd)
                continue
            try:
                fd = os.open(nombre, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
            except OSError:
                continue                      # enlace simbólico o nodo especial: se ignora
            try:
                st = os.fstat(fd)
                if not _stat.S_ISREG(st.st_mode):
                    continue                  # sólo archivos regulares
                count += 1
                if count > MAX_MEMBERS:
                    raise UnsafeArchive("demasiados archivos en el directorio (>%d)" % MAX_MEMBERS)
                destino = os.path.join(dest, rel, nombre)
                os.makedirs(os.path.dirname(destino), exist_ok=True)
                leidos = _copy_fd_to(destino, fd, MAX_MEMBER_BYTES)
                total += leidos
                if total > MAX_EXPANDED_BYTES:
                    raise UnsafeArchive("el directorio excede el tamaño total admitido")
            finally:
                os.close(fd)

    raiz_fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        os.makedirs(dest, exist_ok=True)
        recorrer(raiz_fd, "")
    finally:
        os.close(raiz_fd)
    return total


def copy_tree_no_symlinks(src, dest):
    """Copia un directorio SIN seguir enlaces simbólicos y con los mismos límites
    que un archivo comprimido.

    `shutil.copytree(symlinks=False)` hace lo CONTRARIO de lo que sugiere el nombre:
    no preserva el enlace, sigue el destino y copia su contenido. Un enlace dentro
    del paquete apuntando a `/etc` o a otro directorio del sistema metía archivos
    ajenos en la copia "saneada". Verificado reproduciendo el caso.
    """
    total = 0
    count = 0
    src = os.path.abspath(src)
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue                      # el enlace no se sigue ni se copia
            count += 1
            if count > MAX_MEMBERS:
                raise UnsafeArchive("demasiados archivos en el directorio (>%d)" % MAX_MEMBERS)
            size = os.path.getsize(full)
            if size > MAX_MEMBER_BYTES:
                raise UnsafeArchive("archivo demasiado grande: %r" % fn)
            total += size
            if total > MAX_EXPANDED_BYTES:
                raise UnsafeArchive("el directorio excede el tamaño total admitido")
            rel = os.path.relpath(full, src)
            out = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            shutil.copyfile(full, out, follow_symlinks=False)
    return total


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
    """Devuelve (raíz, modo, sha256_de_la_entrada, bytes_de_la_entrada).

    Toma una INSTANTÁNEA privada primero y hashea ESA instantánea. Antes se
    hasheaba el original y después se volvía a abrir para materializarlo: entre
    los dos momentos se podía sustituir el archivo, y el manifiesto terminaba
    firmando el hash de uno mientras la copia salía del otro. Ahora el hash
    describe exactamente los bytes que se procesaron, por construcción.
    """
    root = os.path.join(workdir, "input")
    os.makedirs(root, exist_ok=True)

    if os.path.isdir(src):
        base = os.path.basename(os.path.abspath(src))
        snap = os.path.join(root, base)
        snapshot_tree(src, snap)
        sha, total = sha256_tree(snap)          # sobre la instantánea, no el original
        return root, "directory", sha, total

    # Archivo: copiarlo por descriptor y trabajar sólo con esa copia.
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        import stat as _stat
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            raise UnsafeArchive("la entrada no es un archivo regular")
        copia = os.path.join(workdir, "entrada.bin")
        leidos = _copy_fd_to(copia, fd, MAX_ARCHIVE_BYTES)
    finally:
        os.close(fd)

    sha = sha256_file(copia)
    if tarfile.is_tarfile(copia):
        extract_tar(copia, root)
        return root, "tar", sha, leidos
    if zipfile.is_zipfile(copia):
        extract_zip(copia, root)
        return root, "zip", sha, leidos
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
    if cls == "password_assignment":
        v = value.strip("\"' ")
        if len(v) < 6:
            return True
        # Valores de configuración que no son secretos por más que la clave se
        # llame `token` o `secret`.
        if v.lower() in {"default", "enabled", "disabled", "true", "false", "none",
                         "null", "auto", "always", "never", "required", "optional",
                         "unlimited", "inherit", "system", "custom"}:
            return True
        if v.isdigit():
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
        # Antes se analizaba solo el principio y la cola se copiaba SIN MIRAR a la
        # salida: un secreto pasado el límite salía intacto. Ahora es el llamador
        # quien decide, y lo que decide es bloquear el archivo entero.
        raise TooLargeToInspect(len(text))
    text_head, text_tail = text, ""

    spans = []  # (inicio, fin, reemplazo, cls, severidad, accion, huella)

    for det in DETECTORS:
        for m in det.rx.finditer(text_head):
            value, start, end = det.pick(m)
            if not value or _noise(det.cls, value):
                continue
            action = policy.get(det.severity, ACT_REVIEW)
            fp = pseudo.fingerprint(det.cls, value)
            # TODO hallazgo se enmascara, incluido el marcado para revisión. Antes,
            # un hallazgo REVIEW dejaba el valor ORIGINAL en la copia: el archivo
            # "saneado" salía con el dato en claro y el estado solo cambiaba el
            # código de salida. La revisión decide si se RESTAURA, no si se tapa.
            repl = (pseudo.token(det.cls, value) if action == ACT_PSEUDONYMIZE
                    else pseudo.review_token(det.cls, value))
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
        # Antes se descartaba el candidato ENTERO si tocaba cualquier span ya
        # reclamado: un valor como `prefijo-entropico-sk-xxxx` quedaba con sólo el
        # sufijo exacto enmascarado y el prefijo en claro. Ahora se recorta.
        libres = [(s, e)]
        for cs, ce in claimed:
            nuevos = []
            for a, b in libres:
                if b <= cs or a >= ce:
                    nuevos.append((a, b)); continue
                if a < cs: nuevos.append((a, cs))
                if b > ce: nuevos.append((ce, b))
            libres = nuevos
        if not libres or libres == []:
            continue
        if libres != [(s, e)]:
            for a, b in libres:
                trozo = text_head[a:b]
                if len(trozo) < 12 or is_placeholder(trozo):
                    continue
                if shannon_entropy(trozo) < profile["entropy_min_bits"]:
                    continue
                spans.append((a, b, pseudo.review_token("high_entropy_string", trozo),
                              "high_entropy_string", SEV_MEDIUM, ACT_REVIEW,
                              pseudo.fingerprint("high_entropy_string", trozo)))
            continue
        val = m.group(1)
        if is_placeholder(val) or val.isdigit() or val.isalpha():
            continue
        if shannon_entropy(val) < profile["entropy_min_bits"]:
            continue
        spans.append((s, e, pseudo.review_token("high_entropy_string", val),
                      "high_entropy_string", SEV_MEDIUM,
                      ACT_REVIEW, pseudo.fingerprint("high_entropy_string", val)))

    if not spans:
        return text, findings

    # Solapamientos: gana el más severo; a igual severidad, el más largo. Y el
    # perdedor se RECORTA en vez de descartarse entero: antes, un término ancho
    # del perfil que contuviera dentro un token crítico hacía que el trozo no
    # cubierto por el ganador saliera en claro.
    spans.sort(key=lambda t: (SEV_ORDER[t[4]], -(t[1] - t[0]), t[0]))
    chosen = []
    for sp in spans:
        start, end = sp[0], sp[1]
        trozos = [(start, end)]
        for c in chosen:
            nuevos = []
            for a, b in trozos:
                if b <= c[0] or a >= c[1]:
                    nuevos.append((a, b))
                    continue
                if a < c[0]:
                    nuevos.append((a, c[0]))
                if b > c[1]:
                    nuevos.append((c[1], b))
            trozos = nuevos
        for a, b in trozos:
            if b - a <= 0:
                continue
            if (a, b) == (start, end):
                chosen.append(sp)
            else:
                # trozo residual: se enmascara igual, con su propio token
                resto = text_head[a:b]
                # El residuo hereda la ACCIÓN del span original: antes usaba
                # siempre pseudo.token(), así que el manifiesto decía "revisar" y
                # la copia no llevaba la marca <REVISAR:…> por ningún lado.
                tok = (pseudo.token(sp[3], resto) if sp[5] == ACT_PSEUDONYMIZE
                       else pseudo.review_token(sp[3], resto))
                chosen.append((a, b, tok, sp[3], sp[4], sp[5],
                               pseudo.fingerprint(sp[3], resto)))
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
        "profile": {"__keys__": {"name", "version", "fingerprint"}},
        "inventory": {"__keys__": {"files_total", "inspected", "blocked", "empty"}},
        "coverage": {"__keys__": {"bytes_inspected", "bytes_not_inspected", "percent_inspected_bp"}},
        "findings": {"__item__": {"__keys__": {"class", "file", "line", "severity",
                                               "action", "fingerprint"}}},
        "blocked_files": {"__item__": {"__keys__": {"file", "reason", "bytes"}}},
    },
}


LEAF_TYPES = {
    "manifest_format": str, "generated_utc": str, "rules_version": str, "status": str,
    "name": str, "version": str, "sha256": str, "mode": str, "bytes": int,
    "files_total": int, "inspected": int, "blocked": int, "empty": int,
    "bytes_inspected": int, "bytes_not_inspected": int, "percent_inspected_bp": int,
    "class": str, "file": str, "line": int, "severity": str, "action": str,
    "fingerprint": str, "reason": str,
    "algorithm": str, "public_key_raw_b64": str, "value_b64": str,
}


def validate_closed(obj, schema, path="$"):
    """Rechaza cualquier clave no declarada Y cualquier hoja con el tipo equivocado.

    Sin la comprobación de tipos, `"status": {"campo_inventado": "PASS"}` pasaba: la
    lista blanca miraba los nombres pero no el contenido de las hojas, así que se
    podían colgar objetos arbitrarios de un campo escalar.
    """
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
        for k in sorted(allowed & set(obj.keys())):
            if k in schema:
                continue
            exp = LEAF_TYPES.get(k)
            v = obj[k]
            if exp is int and isinstance(v, bool):
                errors.append("%s.%s: booleano donde se esperaba un entero" % (path, k))
            elif exp is not None and not isinstance(v, exp):
                errors.append("%s.%s: se esperaba %s y llegó %s"
                              % (path, k, exp.__name__, type(v).__name__))
            elif exp is None and k == "limitations":
                if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                    errors.append("%s.%s: debe ser una lista de cadenas" % (path, k))
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

    # "Sin firmar" tiene su propio veredicto y su propio código, igual que en el
    # verificador del navegador: no es un error de formato, pero tampoco es algo
    # verificado. Antes Python lo trataba como "algoritmo no admitido" (código 2)
    # y la web como un aviso benigno: dos herramientas diciendo cosas distintas
    # del mismo archivo.
    if env["signature"]["algorithm"] == "none":
        return 4, ["SIN FIRMAR — este manifiesto se emitió sin --sign. Describe un proceso,",
                   "pero nada impide que haya sido alterado después: no hay nada que",
                   "comprobar. Trátalo como texto sin respaldo."]
    if env["signature"]["algorithm"] != "Ed25519":
        return 2, ["Algoritmo de firma no admitido: %r" % env["signature"]["algorithm"]]
    try:
        sig = base64.b64decode(env["signature"]["value_b64"], validate=True)
    except Exception:
        return 2, ["Firma con base64 inválido."]

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
def _safe_name(name, pseudo, terms_rx=None):
    """Sanea un nombre antes de escribirlo en la copia o en el manifiesto.

    Los detectores se aplican en UNA sola pasada sobre el texto original. Al
    aplicarlos en cascada, el token de reemplazo de un detector caía dentro del
    patrón del siguiente y salía anidado: `<GITHUB_TOKEN:<PASSWORD_ASSIGNMENT:…>>`.
    La extensión conocida se preserva: un paquete cuyos archivos pierden el
    sufijo deja de ser diagnosticable, que es justo lo que no queremos.
    """
    if len(name) > 512:
        name = name[:512] + "\u2026"
    raiz, ext = os.path.splitext(name)
    if ext.lower() not in INSPECTABLE_EXT and ext.lower() not in UNINSPECTABLE_EXT:
        raiz, ext = name, ""

    spans = []
    if terms_rx is not None:
        for m in terms_rx.finditer(raiz):
            spans.append((m.start(), m.end(), pseudo.token("term", m.group(0)), SEV_HIGH))
    for det in DETECTORS:
        if det.cls == "private_key_pem":
            continue
        for m in det.rx.finditer(raiz):
            valor, a, b = det.pick(m)
            if not valor or _noise(det.cls, valor):
                continue
            spans.append((a, b, pseudo.token(det.cls, valor), det.severity))
    for m in HIGH_ENTROPY_RX.finditer(raiz):
        v = m.group(1)
        if is_placeholder(v) or v.isalpha() or v.isdigit():
            continue
        if shannon_entropy(v) >= 4.2:
            spans.append((m.start(1), m.end(1),
                          pseudo.review_token("high_entropy_string", v), SEV_MEDIUM))
    if not spans:
        return raiz + ext

    spans.sort(key=lambda t: (SEV_ORDER[t[3]], -(t[1] - t[0]), t[0]))
    elegidos = []
    for sp in spans:
        if any(sp[0] < c[1] and c[0] < sp[1] for c in elegidos):
            continue
        elegidos.append(sp)
    elegidos.sort(key=lambda t: t[0])
    out, cur = [], 0
    for a, b, tok, _sev in elegidos:
        out.append(raiz[cur:a]); out.append(tok); cur = b
    out.append(raiz[cur:])
    return "".join(out) + ext


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
    pseudo = Pseudonymizer()
    # El hash del perfil se SALA. Sin sal era un oráculo de diccionario: el perfil
    # contiene `extra_terms` — nombres de clientes, proyectos y plantas, todos de
    # baja entropía — así que cualquiera con una lista de candidatos podía
    # confirmar cuáles están dentro probando hashes contra el manifiesto público.
    # Con la sal efímera el hash sigue sirviendo para lo único que tiene que
    # servir: comparar dos ejecuciones del MISMO paquete, no identificar el perfil.
    profile_sha = pseudo.fingerprint("profile", _canonical(profile).decode("utf-8"))
    terms_rx = build_terms_rx(profile.get("extra_terms"))

    # "Nunca modifica el original" era falso por DOS vías, y la segunda destruía
    # datos: `--output-name /ruta/al/original.tar.gz` esquivaba esta comprobación
    # —que sólo miraba el directorio— y _pack() truncaba el original con w:gz.
    # Medido: 2755 -> 1774 bytes. Y un --out que fuese enlace hacia la entrada
    # esquivaba commonpath() porque se comparaba con abspath, no con realpath.
    src_real = os.path.realpath(src)
    os.makedirs(os.path.abspath(args.out), exist_ok=True)
    outdir = os.path.realpath(args.out)
    try:
        inside = os.path.commonpath([src_real, outdir]) == src_real
    except ValueError:
        inside = False
    if os.path.isdir(src_real) and inside:
        die("--out (%s) queda dentro de la entrada (%s). La salida no puede escribirse "
            "dentro del paquete original." % (outdir, src_real))

    if args.output_name is not None:
        n = args.output_name
        if os.path.isabs(n) or re.search(r"[\\/]", n) or n in (".", "..") or n.startswith("."):
            die("--output-name debe ser un nombre de archivo simple, sin rutas ni "
                "separadores ni empezar con punto. Recibido: %r" % n)
    workdir = tempfile.mkdtemp(prefix="precinto-")
    sanitized_root = os.path.join(workdir, "sanitized")
    os.makedirs(sanitized_root, exist_ok=True)


    findings, blocked = [], []
    n_files = n_inspected = n_empty = 0
    bytes_inspected = bytes_blocked = 0
    memo_rutas = {}

    try:
        root, mode, in_sha, in_bytes = materialize(src, workdir)

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
                rel_seguro = _safe_relname(rel, pseudo, terms_rx, memo_rutas)
                if size == 0:
                    n_empty += 1
                    _copy_into(sanitized_root, rel_seguro, b"")
                    continue

                verdict, reason = classify(rel, abspath, profile)
                if verdict == "block":
                    blocked.append(OrderedDict([("file", rel_seguro),
                                                ("reason", reason), ("bytes", size)]))
                    bytes_blocked += size
                    continue

                if size > MAX_MEMBER_BYTES:
                    blocked.append(OrderedDict([("file", rel_seguro),
                                                ("reason", "excede el tamaño inspeccionable"),
                                                ("bytes", size)]))
                    bytes_blocked += size
                    continue
                with open(abspath, "rb") as fh:
                    raw = fh.read()
                text = raw.decode("utf-8", errors="replace")
                try:
                    clean, f = scan_text(text, rel_seguro, profile,
                                         pseudo, terms_rx)
                except TooLargeToInspect:
                    blocked.append(OrderedDict([("file", rel_seguro),
                                                ("reason", "excede el tamaño inspeccionable"),
                                                ("bytes", size)]))
                    bytes_blocked += size
                    continue
                findings.extend(f)
                n_inspected += 1
                bytes_inspected += size
                _copy_into(sanitized_root, rel_seguro, clean.encode("utf-8"))

        total_bytes = bytes_inspected + bytes_blocked
        pct = (100.0 * bytes_inspected / total_bytes) if total_bytes else 100.0
        needs_review = [f for f in findings if f.action == ACT_REVIEW]
        status = "BLOCKED" if blocked else ("REVIEW" if needs_review else "PASS")

        # El nombre declara el estado. Antes salía siempre `*.sanitized.tar.gz`,
        # con lo que un paquete con decisiones pendientes era indistinguible de uno
        # liberado: alguien lo adjuntaba y listo. Lo que no pasó, no sale con
        # nombre de "listo para enviar".
        sufijo = {"PASS": ".saneado.tar.gz",
                  "REVIEW": ".RETENIDO-requiere-revision.tar.gz",
                  "BLOCKED": ".RETENIDO-con-bloqueos.tar.gz"}[status]
        out_name = args.output_name or (_base_no_ext(src) + sufijo)
        out_path = os.path.join(outdir, out_name)
        # Comprobación final sobre la ruta ya resuelta: ni el destino ni el
        # manifiesto pueden caer fuera de outdir ni sobre la entrada.
        out_real = os.path.realpath(out_path)
        if os.path.dirname(out_real) != outdir:
            die("el destino resuelto (%s) queda fuera de --out (%s)" % (out_real, outdir))
        if out_real == src_real:
            die("el destino coincide con la entrada: no se sobrescribe el original")
        # Escribir a un temporal exclusivo y renombrar: si algo falla a mitad, el
        # destino no queda con un tar truncado.
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=".precinto-", suffix=".part", dir=outdir)
        os.close(tmp_fd)
        try:
            _pack(sanitized_root, tmp_path)
            os.replace(tmp_path, out_path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

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
            ("input", OrderedDict([("name", _safe_name(os.path.basename(src), pseudo, terms_rx)),
                                   ("sha256", in_sha),
                                   ("bytes", in_bytes),
                                   ("mode", mode)])),
            ("output", OrderedDict([("name", _safe_name(os.path.basename(out_path), pseudo, terms_rx)),
                                    ("sha256", sha256_file(out_path)),
                                    ("bytes", os.path.getsize(out_path))])),
            ("profile", OrderedDict([("name", _safe_name(profile["name"], pseudo, terms_rx)),
                                     ("version", _safe_name(profile["version"], pseudo, terms_rx)),
                                     ("fingerprint", profile_sha)])),
            ("rules_version", RULES_VERSION),
            ("inventory", OrderedDict([("files_total", n_files), ("inspected", n_inspected),
                                       ("blocked", len(blocked)), ("empty", n_empty)])),
            # base 10000 (8697 = 86,97 %). Es entero A PROPOSITO: un flotante
            # se serializa distinto en Python (50.0) que en JavaScript (50), y la
            # firma se calcula sobre esos bytes -> el verificador del navegador
            # no podria reproducir la cadena canonica. Sin flotantes, no hay
            # ambiguedad posible entre implementaciones.
            ("coverage", OrderedDict([("bytes_inspected", bytes_inspected),
                                      ("bytes_not_inspected", bytes_blocked),
                                      ("percent_inspected_bp", int(round(pct * 100)))])),
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


def _safe_relname(rel, pseudo, terms_rx, memo):
    """Sanea cada componente de la ruta ANTES de escribir la copia.

    Antes el saneo era sólo para el manifiesto: un archivo `ghp_<token>.log` con
    el contenido limpio salía del perímetro igual, con el secreto en el NOMBRE
    dentro del tar, y el estado podía ser PASS. El memo mantiene la resolución
    determinista y evita que dos nombres distintos colapsen en el mismo.
    """
    if rel in memo:
        return memo[rel]
    partes = []
    for comp in rel.replace(os.sep, "/").split("/"):
        limpio = _safe_name(comp, pseudo, terms_rx)
        partes.append(limpio)
    nuevo = "/".join(partes)
    if nuevo != rel and nuevo in memo.values():
        nuevo = "%s~%d" % (nuevo, len(memo))
    memo[rel] = nuevo
    return nuevo


def _copy_into(root, rel, data):
    dst = os.path.join(root, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as fh:
        fh.write(data)


def _pack(root, out_path):
    """Empaqueta normalizando la metadata.

    `tf.add()` copia propietario, grupo, permisos y fechas de los archivos
    temporales: eso filtra el usuario y el grupo de la máquina que ejecutó
    Precinto dentro de un paquete que va a salir de la organización.
    """
    with tarfile.open(out_path, "w:gz") as tf:
        for dirpath, _dirs, files in os.walk(root):
            for fn in sorted(files):
                full = os.path.join(dirpath, fn)
                arc = os.path.relpath(full, root)
                info = tf.gettarinfo(full, arcname=arc)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o644
                info.mtime = 0
                with open(full, "rb") as fh:
                    tf.addfile(info, fh)


def _report(manifest, findings, out_path, man_path, signed):
    by_class = Counter(f.cls for f in findings)
    by_sev = Counter(f.severity for f in findings)
    st = manifest["status"]
    icon = {"PASS": "PASA", "REVIEW": "REVISAR", "BLOCKED": "BLOQUEADO"}[st]
    print("")
    print("  precinto %s — %s" % (TOOL_VERSION, manifest["profile"]["name"]))
    print("  " + "─" * 66)
    print("  Estado                 %s" % icon)
    print("  Archivos               %d totales · %d inspeccionados · %d bloqueados · %d vacíos"
          % (manifest["inventory"]["files_total"], manifest["inventory"]["inspected"],
             manifest["inventory"]["blocked"], manifest["inventory"]["empty"]))
    print("  Cobertura              %.2f%% de los bytes inspeccionados"
          % (manifest["coverage"]["percent_inspected_bp"] / 100.0))
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
    workdir = tempfile.mkdtemp(prefix="precinto-bench-")
    sanitized_all = []          # texto que SÍ sale del perímetro
    blocked_rel = set()
    flagged_at = set()          # (archivo, línea) marcados para revisión
    total_lines = 0
    try:
        content_root, _mode, _sha, _b = materialize(root, workdir)
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
def _version():
    """La versión sale de los metadatos de la distribución instalada.

    Duplicarla en el código y en el empaquetado garantiza que un día alguien toque
    uno solo. La constante del paquete queda como reserva para cuando se corre
    desde el checkout sin instalar.
    """
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("precinto")
        except PackageNotFoundError:
            pass
    except Exception:
        pass
    try:
        from . import __version__
        return __version__
    except Exception:
        return TOOL_VERSION


def die(msg, code=2):
    sys.stderr.write("precinto: %s\n" % msg)
    raise SystemExit(code)


def main(argv=None):
    p = argparse.ArgumentParser(prog="precinto", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version="precinto " + _version())
    sub = p.add_subparsers(dest="cmd")

    d = sub.add_parser("demo", help="genera el banco sintético con canarios")
    d.add_argument("--out", default="demo")

    sub.add_parser("perfiles", help="lista los perfiles incluidos")

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

    if args.cmd == "demo":
        from .demo import generar
        generar(args.out)
        return 0
    if args.cmd == "perfiles":
        nombres = perfiles_incluidos()
        print("")
        print("  Perfiles incluidos (usalos con --profile <nombre>):")
        for n in nombres:
            print("    %s" % n)
        print("")
        print("  También podés pasar la ruta a un archivo de perfil propio.")
        print("")
        return 0
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
