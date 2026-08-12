#!/usr/bin/env python3
"""
Genera un paquete de diagnóstico SINTÉTICO con canarios plantados y su registro.

Ningún valor de acá es real: son secretos fabricados con el formato correcto para
que los detectores tengan que encontrarlos. Sirve para dos cosas:

  1. Medir el recall del gate sin tocar datos de nadie (`precinto.py bench`).
  2. Mostrarle a un fabricante el antes/después sin pedirle un solo archivo suyo.
     Eso es lo que permite hacer la primera demostración sin acuerdo de
     confidencialidad, y es justamente el punto que destraba la venta escrita.

Uso:  python3 make_canary_bundle.py --out demo/
"""

import argparse
import json
import os
import random
import string
import tarfile
from collections import OrderedDict

R = random.Random(20260811)  # determinista: el mismo banco en cada corrida


def rnd(n, alphabet=string.ascii_letters + string.digits):
    return "".join(R.choice(alphabet) for _ in range(n))


def b64ish(n):
    return "".join(R.choice(string.ascii_letters + string.digits + "+/") for _ in range(n))


CANARIES = []


def plant(cls, value, file, line_hint=""):
    cid = "C%03d" % (len(CANARIES) + 1)
    CANARIES.append(OrderedDict([("id", cid), ("class", cls), ("value", value),
                                 ("file", file), ("line", line_hint)]))
    return value


def build_files():
    f = OrderedDict()

    # ── logs/app.log — el archivo típico donde se cuela todo ────────────────
    aws_id = plant("aws_access_key_id", "AKIA" + rnd(16, string.ascii_uppercase + string.digits),
                   "logs/app.log")
    jwt = plant("jwt", "eyJ%s.eyJ%s.%s" % (b64ish(30).replace("+", "a").replace("/", "b"),
                                           b64ish(48).replace("+", "c").replace("/", "d"),
                                           b64ish(32).replace("+", "e").replace("/", "f")),
                "logs/app.log")
    conn = plant("connection_string_with_password",
                 "postgres://svc_billing:%s@db-prod-01.internal:5432/billing" % rnd(22),
                 "logs/app.log")
    mail = plant("email", "marta.iribarne@clienteindustrial.de", "logs/app.log")
    ip = plant("ipv4", "10.42.17.203", "logs/app.log")
    bearer = plant("bearer_token", rnd(48), "logs/app.log")
    f["logs/app.log"] = "\n".join([
        "2026-08-10T04:12:03Z INFO  starting worker pool size=8",
        "2026-08-10T04:12:04Z DEBUG s3 client configured region=eu-central-1 key=%s" % aws_id,
        "2026-08-10T04:12:09Z WARN  retry 1/3 upstream=%s timeout=30s" % ip,
        "2026-08-10T04:12:11Z DEBUG outbound Authorization: Bearer %s" % bearer,
        "2026-08-10T04:13:44Z ERROR could not open pool dsn=%s" % conn,
        "2026-08-10T04:13:45Z INFO  notifying owner=%s" % mail,
        "2026-08-10T04:14:02Z DEBUG session token=%s" % jwt,
        "2026-08-10T04:14:10Z INFO  healthcheck ok latency_ms=12",
        "2026-08-10T04:15:00Z INFO  request from 8.8.8.8 (no deberia contar: ruido conocido)",
        "2026-08-10T04:15:01Z INFO  bind 0.0.0.0:8080 (ruido conocido)",
    ]) + "\n"

    # ── config/application.yaml ─────────────────────────────────────────────
    pwd = plant("password_assignment", rnd(20), "config/application.yaml")
    api = plant("password_assignment", rnd(32), "config/application.yaml")
    f["config/application.yaml"] = "\n".join([
        "server:",
        "  host: 0.0.0.0",
        "  port: 8080",
        "database:",
        "  user: svc_billing",
        "  password: %s" % pwd,
        "integrations:",
        "  crm_api_key: %s" % api,
        "  webhook: https://hooks.example.com/inbound   # dominio de ejemplo: ruido",
        "  placeholder_secret: <CHANGE_ME>              # placeholder: no debe contar",
        "  disabled_token: REDACTED                     # ya redactado: no debe contar",
    ]) + "\n"

    # ── config/.env ─────────────────────────────────────────────────────────
    gh = plant("github_token", "ghp_" + rnd(36), "config/.env")
    sk = plant("openai_key", "sk-" + rnd(40), "config/.env")
    stripe = plant("stripe_key", "sk_live_" + rnd(24), "config/.env")
    f["config/.env"] = "\n".join([
        "NODE_ENV=production",
        "GITHUB_TOKEN=%s" % gh,
        "LLM_API_KEY=%s" % sk,
        "STRIPE_SECRET=%s" % stripe,
        "FEATURE_FLAG_NEW_UI=true",
    ]) + "\n"

    # ── credenciales PEM sueltas dentro del paquete ─────────────────────────
    pem_body = "\n".join(b64ish(64) for _ in range(6))
    pem = plant("private_key_pem",
                "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----" % pem_body,
                "certs/service.key.txt")
    f["certs/service.key.txt"] = "clave de servicio exportada por el operador\n%s\n" % pem

    # ── soporte/diagnostics.json — nombres internos en prosa ────────────────
    term = plant("profile_term", "Proyecto Vulcano", "support/diagnostics.json")
    cliente = plant("profile_term", "Metalúrgica Sarandí", "support/diagnostics.json")
    slack = plant("slack_token", "xoxb-" + rnd(12, string.digits) + "-" + rnd(24),
                  "support/diagnostics.json")
    f["support/diagnostics.json"] = json.dumps({
        "tenant": cliente,
        "programme": term,
        "notifier": {"slack_bot_token": slack},
        "nodes": [{"name": "node-a", "addr": "192.168.14.7"},
                  {"name": "node-b", "addr": "192.168.14.8"}],
        "notes": "Escalado por el equipo de %s durante la migracion de %s" % (cliente, term),
    }, indent=2, ensure_ascii=False) + "\n"

    # ── entropía sin clasificar: debe ir a REVISAR, no autoredactarse ───────
    ent = plant("high_entropy_string", b64ish(56).replace("+", "Q").replace("/", "Z"),
                "logs/worker.log")
    f["logs/worker.log"] = "\n".join([
        "2026-08-10T05:00:00Z INFO  job queued",
        "2026-08-10T05:00:01Z DEBUG opaque payload signature=%s" % ent,
        "2026-08-10T05:00:02Z INFO  job done in 1.2s",
        "2026-08-10T05:00:03Z INFO  build 4f2b1c9de8a7 (hash corto: no deberia disparar)",
    ]) + "\n"

    # ── ruido legítimo que NO debe romperse: diagnóstico útil ───────────────
    f["logs/gc.log"] = "\n".join(
        "2026-08-10T05:0%d:00Z GC pause young %dms heap %dM->%dM" % (i, 8 + i, 900 - i, 400 + i)
        for i in range(9)) + "\n"

    # ── archivos no inspeccionables: deben BLOQUEARSE enteros ───────────────
    hidden = plant("private_key_pem",
                   "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----"
                   % "\n".join(b64ish(64) for _ in range(4)),
                   "dumps/heap.hprof")
    f["dumps/heap.hprof"] = ("\x00\x01BINARY-HEAP-DUMP\x00" + hidden + "\x00" * 64)
    f["reports/incident.pdf"] = "%PDF-1.7\n\x00 contenido binario simulado \x00\n%%EOF\n"
    f["certs/keystore.jks"] = "\x00\xfe\xed\xfe\xed binario \x00"

    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="demo")
    args = ap.parse_args()
    generar(args.out)


def generar(out):
    outdir = os.path.abspath(out)
    os.makedirs(outdir, exist_ok=True)

    files = build_files()
    stage = os.path.join(outdir, "_stage")
    if os.path.isdir(stage):
        import shutil
        shutil.rmtree(stage)
    for rel, content in files.items():
        p = os.path.join(stage, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(content)

    # línea real de cada canario, para el informe de fallos
    for c in CANARIES:
        content = files.get(c["file"], "")
        for i, line in enumerate(content.splitlines(), 1):
            if c["value"].splitlines()[0] in line:
                c["line"] = i
                break

    bundle = os.path.join(outdir, "support-bundle-demo.tar.gz")
    with tarfile.open(bundle, "w:gz") as tf:
        for dirpath, _d, fns in os.walk(stage):
            for fn in sorted(fns):
                full = os.path.join(dirpath, fn)
                tf.add(full, arcname=os.path.relpath(full, stage))

    ledger_path = os.path.join(outdir, "canaries.json")
    with open(ledger_path, "w", encoding="utf-8") as fh:
        json.dump({"generated_by": "make_canary_bundle.py",
                   "note": "Valores sintéticos. Ninguno es una credencial real.",
                   "canaries": CANARIES}, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    import shutil
    shutil.rmtree(stage, ignore_errors=True)
    print("Paquete de demostración  %s" % bundle)
    print("Registro de canarios     %s  (%d canarios en %d clases)"
          % (ledger_path, len(CANARIES), len(set(c["class"] for c in CANARIES))))


if __name__ == "__main__":
    main()
