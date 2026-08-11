# Precinto

Control de salida para paquetes de diagnóstico (*support bundles*).

Toma el paquete que un cliente debe enviarle al fabricante de su software cuando algo
falla, produce una **copia saneada** y un **manifiesto firmado** de lo que se hizo, y
**bloquea la salida** mientras queden archivos no inspeccionables o hallazgos sin resolver.

No promete «este paquete ya no contiene secretos». Promete:

> «Este paquete fue procesado por la política X versión Y, con estas transformaciones
> y estas limitaciones comprobables.»

Esa diferencia es el producto entero. Nadie puede garantizar lo primero; lo segundo es
verificable por un tercero y es lo que un fabricante puede poner en su documentación.

## Por qué tiene que correr localmente

No es una preferencia de arquitectura: es una imposibilidad de la alternativa. **Nadie
puede mandar su paquete lleno de datos sensibles a un servicio en la nube para preguntarle
si contiene datos sensibles.** La circularidad obliga a que la herramienta viva del lado
del cliente.

## Uso

```bash
python3 make_canary_bundle.py --out demo          # paquete sintético con canarios
python3 precinto.py keygen --out claves         # par Ed25519

python3 precinto.py scan demo/support-bundle-demo.tar.gz \
        --profile perfiles/demo.json --out demo/salida --sign claves/private.pem

python3 precinto.py verify demo/salida/manifest.json --public-key claves/public.pem
python3 precinto.py bench demo/support-bundle-demo.tar.gz \
        --canaries demo/canaries.json --profile perfiles/demo.json
```

Códigos de salida de `scan`: `0` PASA · `3` REVISAR · `4` BLOQUEADO.
De `verify`: `0` procedencia probada · `2` inválido · `3` integridad sí, procedencia **no**.

## Invariantes

1. **Nunca modifica el original.** Siempre escribe una copia nueva.
2. **Cero red, cero subprocesos, ninguna credencial de servicio.** Hay un test que corre
   un escaneo completo con `socket.socket`, `create_connection` y `getaddrinfo` anulados y
   falla si algo intenta usarlos. La única clave que toca es la tuya, local, al firmar.
3. **El manifiesto nunca contiene el valor de un secreto** — solo clase, ubicación y una
   huella salada e irreversible.
4. **Lista blanca cerrada** en el sobre firmado, en todos los niveles: raíz, sub-bloques
   y cada elemento de lista. Un campo extra invalida la firma. Y el perfil también es
   lista blanca cerrada.
5. **No se informa de más.** Verificar la firma contra la clave que viaja dentro del
   propio archivo es circular: eso devuelve **NO PROBADA** y código de salida 3, nunca
   «verificada».

## Pseudonimización

HMAC con sal **efímera**, generada por ejecución y nunca persistida.

- El mismo valor produce el mismo token **dentro de un paquete** → se preserva la
  correlación («este usuario aparece en cuatro archivos») sin revelar el valor.
- Otra ejecución produce otra sal → no se pueden cruzar dos paquetes ni revertir por
  diccionario.

## Licencia

**AGPL-3.0** (ver `LICENSE`) + licencia comercial por producto para redistribuir dentro
de software propietario (ver `COMERCIAL.md`). El hecho por el que se cobra no es usar la
herramienta: es redistribuirla dentro de un producto cerrado. Molde: wolfSSL.

## Qué se instala y qué se visita

|  | Qué es | Dónde corre |
|---|---|---|
| **Se instala** | `precinto.py` — un archivo, sin servicio ni demonio ni puerto | En la máquina del cliente |
| **Se visita** | `sitio/` — landing y verificador de manifiestos | Estático. El verificador valida la firma **dentro del navegador** |

**No hay nada que correr en un servidor.** No hay API, ni cuenta, ni panel, ni licencias
que se comprueben contra un servicio. Es una consecuencia del diseño, no una carencia:
un producto que sostiene que los datos no deben salir del perímetro no puede pedir que
le manden nada.

## Estado

Maqueta de validación, no producto. Existe para dos cosas:

1. Medir el recall sobre canarios sintéticos, sin tocar datos de nadie.
2. Mostrarle a un fabricante el antes/después **sin pedirle un solo archivo suyo** —
   lo que permite la primera demostración sin acuerdo de confidencialidad.

Antes de convertirlo en producto hay que cerrar el paso comercial: que un fabricante
pague por el resultado. La línea de base competitiva obligatoria es Gitleaks, Presidio
y los *redactors* de troubleshoot.sh; si un fabricante solo necesita eso, no es cliente.

## Línea de base y prueba de expulsión

No hay ningún modelo de aprendizaje automático en esta versión, a propósito. Todo es
determinista. Un modelo pequeño solo entra si supera esta línea de base en datos
retenidos de otro sitio y otra fecha — y si no la supera, **se elimina**, no se conserva
por marketing.

## Contacto

Licencias comerciales, fallos o desacuerdos con el enfoque: **precinto@eleata.io**
o un asunto en el repositorio. No mandes paquetes de diagnóstico: no los quiero ver.

## Tests

```bash
python3 test_precinto.py       # 49 comprobaciones
node test_verificador_web.js   # 26 sobre el verificador del navegador
```
