#!/usr/bin/env python3
"""
Tests de regresión de bundlegate. Sin red, sin dependencias externas salvo
`cryptography`. Se corren con:  python3 test_bundlegate.py

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
import bundlegate as bg  # noqa: E402

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


def _minimal_manifest():
    from collections import OrderedDict
    return OrderedDict([
        ("manifest_format", "1.0"),
        ("tool", OrderedDict([("name", "bundlegate"), ("version", "0.1.0")])),
        ("generated_utc", "2026-08-11T00:00:00Z"),
        ("input", OrderedDict([("name", "b.tgz"), ("sha256", "a" * 64),
                               ("bytes", 10), ("mode", "tar")])),
        ("output", OrderedDict([("name", "b.san.tgz"), ("sha256", "b" * 64), ("bytes", 8)])),
        ("profile", OrderedDict([("name", "generic"), ("version", "0.1.0"),
                                 ("sha256", "c" * 64)])),
        ("rules_version", "2026.08.1"),
        ("inventory", OrderedDict([("files_total", 2), ("inspected", 1),
                                   ("blocked", 1), ("empty", 0)])),
        ("coverage", OrderedDict([("bytes_inspected", 5), ("bytes_not_inspected", 5),
                                  ("percent_inspected", 50.0)])),
        ("findings", [OrderedDict([("class", "email"), ("file", "a.log"), ("line", 1),
                                   ("severity", "medium"), ("action", "pseudonymized"),
                                   ("fingerprint", "0" * 16)])]),
        ("blocked_files", [OrderedDict([("file", "x.pdf"), ("reason", "formato"),
                                        ("bytes", 5)])]),
        ("limitations", ["best-effort"]),
        ("status", "BLOCKED"),
    ])


if __name__ == "__main__":
    print("bundlegate — tests de regresión")
    test_closed_whitelist()
    test_provenance_not_proven()
    test_archive_safety()
    test_detection_and_correlation()
    test_manifest_never_leaks()
    test_profile_is_closed()
    print("\n" + "─" * 62)
    print("  %d en verde · %d en rojo" % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("    rojo: %s" % f)
    print("")
    raise SystemExit(1 if FAIL else 0)
