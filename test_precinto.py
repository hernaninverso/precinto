#!/usr/bin/env python3
"""
Tests de regresión de precinto. Sin red, sin dependencias externas salvo
`cryptography`. Se corren con:  python3 test_precinto.py

Los que importan de verdad son los del grupo LISTA BLANCA CERRADA: un campo
extra en CUALQUIER nivel de una estructura firmada tiene que invalidarla. Ese
patrón de fallo apareció en tres sistemas distintos del ecosistema el mismo día,
así que acá se prueba antes de que pueda volver a aparecer.
"""

import copy
import json
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# `precinto.cli` funciona igual desde el checkout y desde el paquete instalado.
# Un `import precinto` a secas resolvía al módulo suelto antes y al paquete después:
# la suite pasaba en el repositorio y explotaba contra la rueda, que es justo el
# escenario que hay que poder probar.
from precinto import cli as bg  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  %s  %s%s" % ("ok  " if cond else "FALLA", name,
                          "" if cond or not detail else "\n         " + detail))


def tmpdir():
    return tempfile.mkdtemp(prefix="bg-test-")


# ─────────────────────────────────────────────────────────────────────────────
def test_closed_whitelist():
    print("\nLISTA BLANCA CERRADA — un campo extra invalida el sobre")
    d = tmpdir()
    try:
        priv, pub = bg.keygen(os.path.join(d, "k"))
        manifest = _minimal_manifest()
        env = bg.sign_envelope(manifest, priv)

        code, _ = bg.verify_envelope(copy.deepcopy(env), pub)
        check("sobre intacto verifica con clave externa (exit 0)", code == 0)

        # raíz
        e = copy.deepcopy(env)
        e["certified_by"] = "un organismo que no existe"
        code, lines = bg.verify_envelope(e, pub)
        check("campo extra en la RAÍZ -> rechazado", code == 2,
              " / ".join(lines[:2]))

        # dentro del manifiesto
        e = copy.deepcopy(env)
        e["manifest"]["_comment"] = "el sistema es fiable, confien"
        code, _ = bg.verify_envelope(e, pub)
        check("campo extra con guion bajo dentro del manifiesto -> rechazado", code == 2)

        # sub-bloque
        e = copy.deepcopy(env)
        e["manifest"]["coverage"]["reliable"] = True
        code, _ = bg.verify_envelope(e, pub)
        check("campo extra en un SUB-BLOQUE (coverage) -> rechazado", code == 2)

        # elemento de lista
        e = copy.deepcopy(env)
        e["manifest"]["findings"].append({
            "class": "x", "file": "f", "line": 1, "severity": "low",
            "action": "flagged_for_review", "fingerprint": "0" * 16, "note": "extra"})
        code, _ = bg.verify_envelope(e, pub)
        check("campo extra en un ELEMENTO DE LISTA -> rechazado", code == 2)

        # bloque de firma
        e = copy.deepcopy(env)
        e["signature"]["issued_by"] = "alguien"
        code, _ = bg.verify_envelope(e, pub)
        check("campo extra en el bloque de FIRMA -> rechazado", code == 2)

        # campo obligatorio ausente
        e = copy.deepcopy(env)
        del e["manifest"]["limitations"]
        code, _ = bg.verify_envelope(e, pub)
        check("campo obligatorio ausente -> rechazado", code == 2)

        # alteración de contenido
        e = copy.deepcopy(env)
        e["manifest"]["status"] = "PASS"
        code, _ = bg.verify_envelope(e, pub)
        check("estado alterado (BLOCKED -> PASS) -> firma inválida", code == 2)

        # un solo bit
        e = copy.deepcopy(env)
        e["manifest"]["coverage"]["bytes_inspected"] += 1
        code, _ = bg.verify_envelope(e, pub)
        check("un solo byte de diferencia -> firma inválida", code == 2)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_provenance_not_proven():
    print("\nPROCEDENCIA — no informar de más")
    d = tmpdir()
    try:
        priv, pub = bg.keygen(os.path.join(d, "k"))
        env = bg.sign_envelope(_minimal_manifest(), priv)
        code, lines = bg.verify_envelope(copy.deepcopy(env), None)
        check("sin clave externa devuelve NO PROBADA (exit 3, no 0)", code == 3)
        check("el texto dice explícitamente que no prueba procedencia",
              any("procedencia" in l.lower() for l in lines))

        # firmado por otra clave: verifica contra la suya propia, pero no contra la nuestra
        priv2, _pub2 = bg.keygen(os.path.join(d, "k2"))
        env2 = bg.sign_envelope(_minimal_manifest(), priv2)
        code_self, _ = bg.verify_envelope(copy.deepcopy(env2), None)
        code_ext, _ = bg.verify_envelope(copy.deepcopy(env2), pub)
        check("un tercero puede firmar y pasar la comprobación interna", code_self == 3)
        check("...pero falla contra la clave pública legítima", code_ext == 2)
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
def test_archive_safety():
    print("\nDESEMPAQUETADO DEFENSIVO")
    d = tmpdir()
    try:
        # path traversal en tar
        p = os.path.join(d, "trav.tar")
        with tarfile.open(p, "w") as tf:
            info = tarfile.TarInfo("../../etc/evil")
            data = b"pwned"
            info.size = len(data)
            tf.addfile(info, __import__("io").BytesIO(data))
        ok = False
        try:
            bg.materialize(p, os.path.join(d, "w1"))
        except bg.UnsafeArchive:
            ok = True
        check("tar con '..' -> UnsafeArchive", ok)

        # ruta absoluta
        p = os.path.join(d, "abs.tar")
        with tarfile.open(p, "w") as tf:
            info = tarfile.TarInfo("/etc/passwd")
            info.size = 3
            tf.addfile(info, __import__("io").BytesIO(b"abc"))
        ok = False
        try:
            bg.materialize(p, os.path.join(d, "w2"))
        except bg.UnsafeArchive:
            ok = True
        check("tar con ruta absoluta -> UnsafeArchive", ok)

        # symlink
        p = os.path.join(d, "sym.tar")
        with tarfile.open(p, "w") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
        ok = False
        try:
            bg.materialize(p, os.path.join(d, "w3"))
        except bg.UnsafeArchive:
            ok = True
        check("tar con enlace simbólico -> UnsafeArchive", ok)

        # zip-slip
        p = os.path.join(d, "slip.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("../../evil.txt", "pwned")
        ok = False
        try:
            bg.materialize(p, os.path.join(d, "w4"))
        except bg.UnsafeArchive:
            ok = True
        check("zip-slip -> UnsafeArchive", ok)

        # bomba de compresión
        p = os.path.join(d, "bomb.tar.gz")
        with tarfile.open(p, "w:gz") as tf:
            info = tarfile.TarInfo("zeros")
            payload = b"\x00" * (40 * 1024 * 1024)
            info.size = len(payload)
            tf.addfile(info, __import__("io").BytesIO(payload))
        ok = False
        try:
            bg.materialize(p, os.path.join(d, "w5"))
        except bg.UnsafeArchive:
            ok = True
        check("ratio de compresión desmedido -> UnsafeArchive", ok)

        # formato desconocido
        p = os.path.join(d, "cualquiera.bin")
        with open(p, "wb") as fh:
            fh.write(b"no soy un archivo comprimido")
        ok = False
        try:
            bg.materialize(p, os.path.join(d, "w6"))
        except bg.UnsafeArchive:
            ok = True
        check("formato no reconocido -> UnsafeArchive", ok)
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
def test_detection_and_correlation():
    print("\nDETECCIÓN Y SANEADO")
    prof = bg.load_profile(None)
    ps = bg.Pseudonymizer()

    pem = ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\nDEFghi\n"
           "-----END RSA PRIVATE KEY-----")
    clean, f = bg.scan_text("clave:\n%s\nfin\n" % pem, "k.txt", prof, ps, None)
    check("clave PEM MULTILÍNEA detectada", any(x.cls == "private_key_pem" for x in f))
    check("la clave PEM no sobrevive en la salida", "BEGIN RSA PRIVATE KEY" not in clean)

    clean, f = bg.scan_text("crm_api_key: s3cr3t0Largo123\n", "c.yaml", prof, ps, None)
    check("'crm_api_key' con prefijo detectado (el \\b se lo comía)",
          any(x.cls == "password_assignment" for x in f))

    txt = "a=juan.perez@empresa.de\nb=juan.perez@empresa.de\nc=otro@empresa.de\n"
    clean, f = bg.scan_text(txt, "e.log", prof, ps, None)
    lines = clean.strip().split("\n")
    check("mismo valor -> mismo pseudónimo (correlación preservada)",
          lines[0].split("=")[1] == lines[1].split("=")[1])
    check("valores distintos -> pseudónimos distintos",
          lines[0].split("=")[1] != lines[2].split("=")[1])

    ps2 = bg.Pseudonymizer()
    c2, _ = bg.scan_text(txt, "e.log", prof, ps2, None)
    check("otra ejecución -> otro pseudónimo (sal efímera, no se cruzan bundles)",
          c2 != clean)

    clean, f = bg.scan_text("password: <CHANGE_ME>\ntoken: REDACTED\nip: 127.0.0.1\n",
                            "n.yaml", prof, ps, None)
    check("placeholders e IP de ruido no generan hallazgos", len(f) == 0,
          "hallazgos: %s" % [x.cls for x in f])

    clean, f = bg.scan_text("mail: alguien@example.com\n", "n2.yaml", prof, ps, None)
    check("dominio de ejemplo (RFC 2606) no cuenta como PII", len(f) == 0)

    gc = "GC pause young 12ms heap 900M->400M\n" * 5
    clean, f = bg.scan_text(gc, "gc.log", prof, ps, None)
    check("una traza de diagnóstico legítima queda intacta", clean == gc and not f)

    clean, f = bg.scan_text("sig: %s\n" % ("Qk8fRt2aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdEF"),
                            "h.log", prof, ps, None)
    ent = [x for x in f if x.cls == "high_entropy_string"]
    check("alta entropía -> MARCADA para revisión, no autoredactada",
          bool(ent) and ent[0].action == bg.ACT_REVIEW)


def test_manifest_never_leaks():
    print("\nEL MANIFIESTO NUNCA LLEVA EL VALOR")
    prof = bg.load_profile(None)
    ps = bg.Pseudonymizer()
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    _clean, f = bg.scan_text("TOKEN=%s\n" % secret, "x.env", prof, ps, None)
    blob = json.dumps([x.as_dict() for x in f])
    check("el valor del secreto no aparece en el manifiesto", secret not in blob)
    check("la huella es salada (no es un sha256 crudo del valor)",
          all(x.fingerprint != __import__("hashlib").sha256(secret.encode()).hexdigest()[:16]
              for x in f))


def test_profile_is_closed():
    print("\nEL PERFIL TAMBIÉN ES LISTA BLANCA CERRADA")
    d = tmpdir()
    try:
        p = os.path.join(d, "malo.json")
        with open(p, "w") as fh:
            json.dump({"name": "x", "campo_inventado": True}, fh)
        ok = False
        try:
            bg.load_profile(p)
        except ValueError:
            ok = True
        check("clave desconocida en el perfil -> ValueError", ok)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_fail_closed():
    """Los fail-open que encontró la auditoría de codex. Cada uno reproducido."""
    print("\nFAIL-CLOSED (hallazgos de la auditoría)")
    d = tmpdir()
    try:
        def perfil(**kw):
            p = json.loads(json.dumps(bg.DEFAULT_PROFILE)); p.update(kw)
            path = os.path.join(d, "p.json")
            with open(path, "w") as fh: json.dump(p, fh)
            return path

        pol = dict(bg.DEFAULT_PROFILE["severity_policy"]); pol["critical"] = "allow"
        ok = False
        try: bg.load_profile(perfil(severity_policy=pol))
        except ValueError: ok = True
        check("perfil con accion 'allow' -> rechazado (dejaba el token intacto y daba PASS)", ok)

        pol2 = dict(bg.DEFAULT_PROFILE["severity_policy"]); del pol2["low"]
        ok = False
        try: bg.load_profile(perfil(severity_policy=pol2))
        except ValueError: ok = True
        check("perfil con una severidad sin declarar -> rechazado", ok)

        ok = False
        try: bg.load_profile(perfil(block_uninspectable=False))
        except ValueError: ok = True
        check("block_uninspectable=false -> rechazado (era fail-open)", ok)

        ok = False
        try: bg.load_profile(perfil(deny_files="no soy una lista"))
        except ValueError: ok = True
        check("deny_files con tipo equivocado -> rechazado", ok)

        prof = bg.load_profile(None); ps = bg.Pseudonymizer()
        ent = "Qk8fRt2aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdEF"
        clean, f = bg.scan_text("sig: %s\n" % ent, "h.log", prof, ps, None)
        check("un hallazgo MARCADO tambien se enmascara (antes salia en claro)",
              ent not in clean and "REVISAR" in clean)

        ok = False
        try: bg.scan_text("x" * (bg.MAX_MEMBER_BYTES + 10), "big.log", prof, ps, None)
        except bg.TooLargeToInspect: ok = True
        check("texto mayor al limite -> TooLargeToInspect (antes copiaba la cola sin mirar)", ok)

        name = bg._safe_name("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8.png", ps)
        check("un token en el NOMBRE del archivo no llega al manifiesto",
              "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" not in name)

        src = os.path.join(d, "bundle"); os.makedirs(src)
        with open(os.path.join(d, "afuera.txt"), "w") as fh: fh.write("SECRETO EXTERNO")
        os.symlink(os.path.join(d, "afuera.txt"), os.path.join(src, "link.txt"))
        with open(os.path.join(src, "propio.log"), "w") as fh: fh.write("linea propia\n")
        dst = os.path.join(d, "copia"); bg.copy_tree_no_symlinks(src, dst)
        check("copiar un directorio NO sigue enlaces simbolicos (importaba archivos de afuera)",
              os.path.exists(os.path.join(dst, "propio.log"))
              and not os.path.exists(os.path.join(dst, "link.txt")))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_leaf_types():
    print("\nLISTA BLANCA — tambien los TIPOS de las hojas")
    d = tmpdir()
    try:
        priv, pub = bg.keygen(os.path.join(d, "k"))
        env = bg.sign_envelope(_minimal_manifest(), priv)
        for name, mut in [
            ("un objeto colgado de 'status'", lambda e: e["manifest"].__setitem__("status", {"x": "PASS"})),
            ("una lista colgada de 'rules_version'", lambda e: e["manifest"].__setitem__("rules_version", ["x"])),
            ("un entero donde va una cadena", lambda e: e["manifest"]["tool"].__setitem__("name", 7)),
            ("una cadena donde va un entero", lambda e: e["manifest"]["inventory"].__setitem__("inspected", "3")),
            ("un booleano donde va un entero", lambda e: e["manifest"]["inventory"].__setitem__("blocked", True)),
            ("limitations con un objeto adentro", lambda e: e["manifest"].__setitem__("limitations", [{"a": 1}])),
        ]:
            t = copy.deepcopy(env); mut(t)
            code, _ = bg.verify_envelope(t, pub)
            check(name + " -> rechazado", code == 2)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_no_network():
    """La suite afirmaba 'cero red comprobado' y la comprobacion NO existia."""
    print("\nCERO RED — comprobado, no prometido")
    import socket
    d = tmpdir()
    guardados = (socket.socket, socket.create_connection, socket.getaddrinfo)
    intentos = []

    def bloqueado(*a, **k):
        intentos.append(a)
        raise AssertionError("intento de red durante el escaneo")
    try:
        src = os.path.join(d, "b"); os.makedirs(src)
        with open(os.path.join(src, "a.log"), "w") as fh:
            fh.write("token=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\nmail=x@corp.de\n")
        priv, _pub = bg.keygen(os.path.join(d, "k"))
        socket.socket = bloqueado
        socket.create_connection = bloqueado
        socket.getaddrinfo = bloqueado

        class A(object):
            bundle = src; profile = None; out = os.path.join(d, "salida")
            output_name = None; sign = priv
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = bg.cmd_scan(A())
        check("un escaneo completo corre con los sockets deshabilitados", code in (0, 3, 4))
        check("cero intentos de red durante el escaneo", not intentos)
        env = json.load(open(os.path.join(d, "salida", "manifest.json")))
        check("el manifiesto se emitio igual", env["manifest"]["status"] in ("PASS", "REVIEW", "BLOCKED"))
    finally:
        socket.socket, socket.create_connection, socket.getaddrinfo = guardados
        shutil.rmtree(d, ignore_errors=True)


def test_segunda_tanda():
    """Los cuatro hallazgos cerrados después de la primera auditoría."""
    print("\nSEGUNDA TANDA DE ARREGLOS")
    d = tmpdir()
    try:
        # #2 hash de árbol reproducible y sensible
        b = os.path.join(d, "b"); os.makedirs(b)
        with open(os.path.join(b, "a.log"), "w") as fh: fh.write("hola\n")
        h1, n1 = bg.sha256_tree(b)
        check("hash de árbol reproducible", bg.sha256_tree(b)[0] == h1 and n1 > 0)
        with open(os.path.join(b, "c.log"), "w") as fh: fh.write("nuevo\n")
        h2, _ = bg.sha256_tree(b)
        check("cambia al agregar un archivo", h1 != h2)
        os.rename(os.path.join(b, "c.log"), os.path.join(b, "d.log"))
        check("cambia al renombrar", bg.sha256_tree(b)[0] != h2)

        priv, _pub = bg.keygen(os.path.join(d, "k"))
        class A(object):
            bundle = b; profile = None; out = os.path.join(d, "o")
            output_name = None; sign = priv
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()): bg.cmd_scan(A())
        man = json.load(open(os.path.join(d, "o", "manifest.json")))["manifest"]
        check("un directorio ya no se firma con sha256 vacío",
              man["input"]["sha256"] != "" and man["input"]["bytes"] > 0)

        # #3 contraseñas con espacios y token genérico
        prof = bg.load_profile(None); ps = bg.Pseudonymizer()
        c, _f = bg.scan_text('password: "correct horse battery staple"\n', "x.yaml", prof, ps, None)
        check("contraseña entrecomillada CON espacios enmascarada entera",
              "correct horse battery staple" not in c and "battery" not in c)
        c, _f = bg.scan_text("token=abc123def456ghi\n", "x.log", prof, ps, None)
        check("token= genérico detectado", "abc123def456ghi" not in c)
        c, f = bg.scan_text("token_count=5\nretry_tokens=3\n", "x.log", prof, ps, None)
        check("token_count=5 NO es un falso positivo", not f)

        # #3 solapamiento: el perdedor se recorta, no se descarta
        prof2 = bg.load_profile(None)
        ancho = "Proyecto Vulcano ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + " fase dos"
        prof2["extra_terms"] = [ancho]
        rx = bg.build_terms_rx(prof2["extra_terms"])
        c, _f = bg.scan_text("ref: " + ancho + "\n", "y.log", prof2, bg.Pseudonymizer(), rx)
        check("solapamiento: nada del término ancho queda en claro",
              "Proyecto Vulcano" not in c and "fase dos" not in c and "ghp_A1b2" not in c)

        # #4 'none' tiene veredicto propio
        env = {"manifest": _minimal_manifest(),
               "signature": {"algorithm": "none", "public_key_raw_b64": "", "value_b64": ""}}
        code, lines = bg.verify_envelope(env, None)
        check("algorithm='none' -> código 4 (sin firmar), no 2", code == 4)
        check("...y lo dice explícitamente", any("SIN FIRMAR" in l for l in lines))
        env["signature"] = {"algorithm": "Ed25519", "public_key_raw_b64": "AA==",
                            "value_b64": "no es base64!!"}
        check("base64 inválido rechazado", bg.verify_envelope(env, None)[0] == 2)

        # #5 hash del perfil salado
        pp = os.path.join(d, "p.json")
        prof3 = json.loads(json.dumps(bg.DEFAULT_PROFILE)); prof3["extra_terms"] = ["Cliente Uno"]
        with open(pp, "w") as fh: json.dump(prof3, fh)
        hs = []
        for i in range(2):
            class B(object):
                bundle = b; profile = pp; out = os.path.join(d, "o%d" % i)
                output_name = None; sign = priv
            with contextlib.redirect_stdout(io.StringIO()): bg.cmd_scan(B())
            hs.append(json.load(open(os.path.join(d, "o%d" % i, "manifest.json")))
                      ["manifest"]["profile"]["fingerprint"])
        crudo = __import__("hashlib").sha256(bg._canonical(bg.load_profile(pp))).hexdigest()
        check("el hash del perfil está salado (no es un oráculo de diccionario)",
              hs[0] != hs[1] and crudo[:16] not in hs)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_tercera_tanda():
    """Bloqueantes y defectos de la SEGUNDA auditoría."""
    print("\nTERCERA TANDA — bloqueantes de la segunda auditoría")
    d = tmpdir()
    try:
        import io, contextlib, hashlib, tarfile
        # El paquete se GENERA acá: depender de `demo/…` del checkout hacía que la
        # suite fallara al correr contra el paquete instalado, que es precisamente
        # la única forma de probar que la rueda no está rota.
        orig = os.path.join(d, "b.tar.gz")
        semilla = os.path.join(d, "semilla"); os.makedirs(semilla)
        with open(os.path.join(semilla, "app.log"), "w") as fh:
            fh.write("token=ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + "\n")
        with tarfile.open(orig, "w:gz") as tf:
            tf.add(os.path.join(semilla, "app.log"), arcname="app.log")
        antes = hashlib.sha256(open(orig, "rb").read()).hexdigest()
        priv, _pub = bg.keygen(os.path.join(d, "k"))

        for nombre, on in [("ruta absoluta al original", orig), ("../ para escapar", "../x.tar.gz"),
                           ("subruta", "sub/x.tar.gz"), ("nombre oculto", ".x.tar.gz")]:
            class A(object):
                bundle = orig; profile = None; out = os.path.join(d, "s"); output_name = on; sign = None
            rechazado = False
            try:
                with contextlib.redirect_stdout(io.StringIO()): bg.cmd_scan(A())
            except SystemExit:
                rechazado = True
            except Exception:
                rechazado = True
            check("--output-name con %s -> rechazado" % nombre, rechazado)
        check("el paquete original quedó intacto",
              hashlib.sha256(open(orig, "rb").read()).hexdigest() == antes)

        # el hash del manifiesto describe los bytes procesados
        class B(object):
            bundle = orig; profile = None; out = os.path.join(d, "o")
            output_name = None; sign = priv
        with contextlib.redirect_stdout(io.StringIO()): bg.cmd_scan(B())
        man = json.load(open(os.path.join(d, "o", "manifest.json")))["manifest"]
        check("el sha declarado coincide con el archivo procesado",
              man["input"]["sha256"] == antes)

        # instantánea inmune a symlinks
        src = os.path.join(d, "bundle"); os.makedirs(os.path.join(src, "sub"))
        with open(os.path.join(d, "EXTERNO.txt"), "w") as fh: fh.write("dato de fuera")
        with open(os.path.join(src, "propio.log"), "w") as fh: fh.write("propio\n")
        with open(os.path.join(src, "sub", "hondo.log"), "w") as fh: fh.write("hondo\n")
        os.symlink(os.path.join(d, "EXTERNO.txt"), os.path.join(src, "link.txt"))
        os.symlink(d, os.path.join(src, "dirlink"))
        snap = os.path.join(d, "snap"); bg.snapshot_tree(src, snap)
        hay = []
        for dp, _dn, fn in os.walk(snap):
            for f in fn: hay.append(os.path.relpath(os.path.join(dp, f), snap))
        check("la instantánea NO copia el enlace a un archivo externo", "link.txt" not in hay)
        check("la instantánea NO sigue un enlace a directorio",
              not any("EXTERNO" in h for h in hay))
        check("la instantánea sí copia lo propio y lo anidado",
              "propio.log" in hay and os.path.join("sub", "hondo.log") in hay)

        # nombres saneados TAMBIÉN en la copia
        b2 = os.path.join(d, "b2"); os.makedirs(b2)
        tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        with open(os.path.join(b2, "%s.log" % tok), "w") as fh: fh.write("limpio\n")
        with open(os.path.join(b2, "ana.perez@cliente.de.log"), "w") as fh: fh.write("otro\n")
        with open(os.path.join(b2, "normal.log"), "w") as fh: fh.write("traza\n")
        class C(object):
            bundle = b2; profile = None; out = os.path.join(d, "o2"); output_name = None; sign = priv
        with contextlib.redirect_stdout(io.StringIO()): bg.cmd_scan(C())
        tp = [f for f in os.listdir(os.path.join(d, "o2")) if f.endswith(".tar.gz")][0]
        with tarfile.open(os.path.join(d, "o2", tp)) as tf:
            nombres = tf.getnames()
            metas = [(m.uid, m.gid, m.uname, m.gname, m.mtime) for m in tf.getmembers()]
        check("un token en el NOMBRE no sale dentro del tar", not any(tok in n for n in nombres))
        check("un email en el NOMBRE no sale dentro del tar",
              not any("ana.perez" in n for n in nombres))
        check("sin anidamiento de tokens en los nombres", not any(":<" in n for n in nombres))
        check("la extensión se preserva", all(n.endswith(".log") for n in nombres))
        check("un nombre inocuo queda intacto", any(n.endswith("normal.log") for n in nombres))
        check("el tar no lleva uid/gid/uname/mtime de la máquina",
              all(m == (0, 0, "", "", 0) for m in metas))

        # falsos positivos destructivos
        prof = bg.load_profile(None); ps = bg.Pseudonymizer()
        for txt, debe in [("password: correct horse battery staple\n", True),
                          ("db.password=simple123\n", True),
                          ("token_count=100000\n", False),
                          ("credential_provider=default\n", False),
                          ("bearer_strategy=enabled\n", False),
                          ("password_policy=strict\n", False)]:
            _c, f = bg.scan_text(txt, "x.yaml", prof, ps, None)
            det = any(x.cls == "password_assignment" for x in f)
            check("%-42s -> %s" % (txt.strip()[:42], "enmascara" if debe else "respeta"), det == debe)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _minimal_manifest():
    from collections import OrderedDict
    return OrderedDict([
        ("manifest_format", "1.0"),
        ("tool", OrderedDict([("name", "precinto"), ("version", "0.1.0")])),
        ("generated_utc", "2026-08-11T00:00:00Z"),
        ("input", OrderedDict([("name", "b.tgz"), ("sha256", "a" * 64),
                               ("bytes", 10), ("mode", "tar")])),
        ("output", OrderedDict([("name", "b.san.tgz"), ("sha256", "b" * 64), ("bytes", 8)])),
        ("profile", OrderedDict([("name", "generic"), ("version", "0.1.0"),
                                 ("fingerprint", "c" * 16)])),
        ("rules_version", "2026.08.1"),
        ("inventory", OrderedDict([("files_total", 2), ("inspected", 1),
                                   ("blocked", 1), ("empty", 0)])),
        ("coverage", OrderedDict([("bytes_inspected", 5), ("bytes_not_inspected", 5),
                                  ("percent_inspected_bp", 5000)])),
        ("findings", [OrderedDict([("class", "email"), ("file", "a.log"), ("line", 1),
                                   ("severity", "medium"), ("action", "pseudonymized"),
                                   ("fingerprint", "0" * 16)])]),
        ("blocked_files", [OrderedDict([("file", "x.pdf"), ("reason", "formato"),
                                        ("bytes", 5)])]),
        ("limitations", ["best-effort"]),
        ("status", "BLOCKED"),
    ])


if __name__ == "__main__":
    print("precinto — tests de regresión")
    test_closed_whitelist()
    test_provenance_not_proven()
    test_archive_safety()
    test_detection_and_correlation()
    test_manifest_never_leaks()
    test_profile_is_closed()
    test_fail_closed()
    test_leaf_types()
    test_no_network()
    test_segunda_tanda()
    test_tercera_tanda()
    print("\n" + "─" * 62)
    print("  %d en verde · %d en rojo" % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("    rojo: %s" % f)
    print("")
    raise SystemExit(1 if FAIL else 0)
