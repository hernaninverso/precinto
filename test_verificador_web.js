#!/usr/bin/env node
/*
 * Regresión del verificador que corre en el navegador (sitio/verificar.html).
 *
 * Extrae el script de la página real —no una copia— y comprueba tres cosas que,
 * si se rompen, dejan el verificador informando de más sin que nadie lo note:
 *
 *   1. La implementación de Ed25519 en BigInt es correcta: acepta firmas hechas
 *      por Python y por Node, y rechaza las de otra clave.
 *   2. La cadena canónica coincide BYTE A BYTE con la de Python. Si divergen, la
 *      firma no valida en el navegador aunque el archivo esté perfecto.
 *   3. La lista blanca cerrada rechaza exactamente lo mismo que el verificador
 *      de línea de comandos, en todos los niveles.
 *
 * Requiere que exista demo/salida/manifest.json firmado. Se corre con:
 *     node test_verificador_web.js
 */
"use strict";
const fs = require("fs");
const path = require("path");
const { generateKeyPairSync, sign } = require("crypto");

const ROOT = __dirname;
const MANIFEST = path.join(ROOT, "demo/salida/manifest.json");
const PUBPEM = path.join(ROOT, "claves/public.pem");

if (!fs.existsSync(MANIFEST) || !fs.existsSync(PUBPEM)) {
  console.error("Faltan artefactos. Generalos antes:\n" +
    "  python3 make_canary_bundle.py --out demo\n" +
    "  python3 precinto.py keygen --out claves\n" +
    "  python3 precinto.py scan demo/support-bundle-demo.tar.gz \\\n" +
    "          --profile perfiles/demo.json --out demo/salida --sign claves/private.pem");
  process.exit(2);
}

// Cargar el núcleo del verificador desde la página real, sin la parte de interfaz.
const html = fs.readFileSync(path.join(ROOT, "sitio/verificar.html"), "utf8");
const script = html.split("<script>")[1].split("</script>")[0];
const core = script.split("/* ─────────────────────────────── interfaz ─")[0];
const mod = {};
new Function("crypto", "module", core +
  "\nmodule.exports={ed25519Verify,canonical,validateClosed,pemToRawEd25519,b64ToBytes,SCHEMA};"
)(globalThis.crypto, mod);
const V = mod.exports;

let ok = 0, bad = 0;
function check(name, cond) {
  if (cond) { ok++; console.log("  ok    " + name); }
  else { bad++; console.log("  FALLA " + name); }
}

(async () => {
  console.log("verificador web — regresión\n");
  const env = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
  const rawPem = V.pemToRawEd25519(fs.readFileSync(PUBPEM, "utf8"));
  const msg = new Uint8Array(Buffer.from(V.canonical(env.manifest), "utf8"));
  const sig = V.b64ToBytes(env.signature.value_b64);

  console.log("CANÓNICA");
  check("el PEM se decodifica a 32 bytes crudos", rawPem && rawPem.length === 32);
  check("la clave embebida coincide con la del PEM",
    Buffer.compare(Buffer.from(V.b64ToBytes(env.signature.public_key_raw_b64)),
                   Buffer.from(rawPem)) === 0);
  check("el manifiesto no contiene ningún flotante",
    (() => { try { V.canonical(env.manifest); return true; } catch (e) { return false; } })());

  console.log("\nFIRMA");
  check("firma válida con la clave externa", await V.ed25519Verify(sig, msg, rawPem));

  const alt = JSON.parse(JSON.stringify(env)); alt.manifest.status = "PASS";
  check("estado alterado BLOCKED->PASS rechazado",
    !(await V.ed25519Verify(sig, new Uint8Array(Buffer.from(V.canonical(alt.manifest), "utf8")), rawPem)));

  const one = JSON.parse(JSON.stringify(env)); one.manifest.coverage.bytes_inspected += 1;
  check("un solo byte de diferencia rechazado",
    !(await V.ed25519Verify(sig, new Uint8Array(Buffer.from(V.canonical(one.manifest), "utf8")), rawPem)));

  const kp = generateKeyPairSync("ed25519");
  const otra = new Uint8Array(sign(null, Buffer.from(msg), kp.privateKey));
  const rawOtra = new Uint8Array(kp.publicKey.export({ type: "spki", format: "der" }).slice(12));
  check("firma de un tercero rechazada contra nuestra clave",
    !(await V.ed25519Verify(otra, msg, rawPem)));
  check("esa misma firma SÍ valida con la clave del tercero (la implementación no está rota)",
    await V.ed25519Verify(otra, msg, rawOtra));

  console.log("\nLISTA BLANCA CERRADA");
  const cases = [
    ["campo extra en la raíz", e => { e.certified_by = "un organismo"; }],
    ["campo con guion bajo en el manifiesto", e => { e.manifest._nota = "confien en mi"; }],
    ["campo extra en un sub-bloque", e => { e.manifest.coverage.reliable = true; }],
    ["campo extra en un elemento de lista", e => { e.manifest.findings[0].note = "x"; }],
    ["campo extra en el bloque de firma", e => { e.signature.issued_by = "alguien"; }],
    ["campo obligatorio ausente", e => { delete e.manifest.limitations; }],
  ];
  for (const [name, mutate] of cases) {
    const t = JSON.parse(JSON.stringify(env)); mutate(t);
    check(name + " rechazado", V.validateClosed(t, V.SCHEMA).length > 0);
  }
  check("el sobre intacto pasa la validación", V.validateClosed(env, V.SCHEMA).length === 0);

  console.log("\n" + "─".repeat(58));
  console.log("  " + ok + " en verde · " + bad + " en rojo\n");
  process.exit(bad ? 1 : 0);
})();
