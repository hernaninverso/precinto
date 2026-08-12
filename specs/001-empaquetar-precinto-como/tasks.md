# Tareas: distribución instalable de Precinto

**Feature**: 001-empaquetar-precinto-como · **Plan**: `plan.md`

## F1 — Reestructurar a paquete

- [x] **T1.1** Crear `precinto/__init__.py` con `__version__` de reserva.
- [x] **T1.2** Mover el motor a `precinto/cli.py` sin cambiar una línea de lógica.
- [x] **T1.3** Mover el generador a `precinto/demo.py`.
- [x] **T1.4** Mover `perfiles/*.json` a `precinto/perfiles/`.
- [x] **T1.5** Dejar `precinto.py` y `make_canary_bundle.py` en la raíz como envoltorios
      delgados, para no romper las instrucciones ya publicadas en el sitio y en los correos.

## F2 — Empaquetar

- [x] **T2.1** `pyproject.toml` PEP 621 con `hatchling`, dependencia única `cryptography`.
- [x] **T2.2** `[project.scripts] precinto = "precinto.cli:main"`.
- [x] **T2.3** Declarar `precinto/perfiles/*.json` como datos del paquete.

## F3 — Resolver perfiles y versión

- [x] **T3.1** `_resolver_perfil(nombre_o_ruta)` con `importlib.resources.files()`;
      **nunca** `__file__`. Acepta ruta (compatibilidad) y nombre (`atlassian-dc`).
- [x] **T3.2** `--version` desde `importlib.metadata.version("precinto")`, con reserva a
      `__version__` cuando se corre desde el checkout sin instalar.
- [x] **T3.3** Subcomando `precinto demo --out X` que envuelve al generador.
- [x] **T3.4** `precinto perfiles` que lista los incluidos: sin esto, un usuario instalado
      no tiene forma de saber qué nombres puede pasarle a `--profile`.

## F4 — Verificar de verdad (los siete criterios de la spec)

- [x] **T4.1** Construir la rueda y **contar los `.json` dentro** (CA-5).
- [x] **T4.2** Instalar en un venv limpio (CA-1).
- [x] **T4.3** `precinto --help` y `--version` **desde `/tmp`** (CA-2).
- [x] **T4.4** `precinto demo` + `scan --profile atlassian-dc` desde `/tmp` (CA-3).
- [x] **T4.5** Escaneo con los sockets anulados contra el paquete instalado (CA-4).
- [x] **T4.6** Suite completa contra lo instalado, no contra el checkout (CA-6).
- [x] **T4.7** Renombrar el checkout y repetir T4.3 y T4.4 (CA-7) — la única prueba que
      detecta la rueda rota, que es el fallo que ya ocurrió tres veces en este ecosistema.

## Fuera de alcance

Publicar en PyPI de verdad: requiere credencial y la decisión de Hernán.


## Resultado

Los siete criterios de aceptación pasan. Lo que encontró la verificación y no habrían
encontrado los tests:

- `force-include` de los perfiles rompía la construcción («a second file is being
  added»): hatchling ya los incluye por estar dentro del paquete. Se quitó **y se
  comprobó contando los `.json` dentro del `.whl`**, que es lo que evita el fallo
  clásico de la rueda sin datos.
- La suite dependía de `demo/…` del checkout, así que fallaba contra el paquete
  instalado — justamente el único escenario que prueba que la rueda no está rota.
  Ahora genera su propio paquete.
- `import precinto as bg` resolvía al módulo suelto antes y al paquete después: pasaba
  en el repositorio y explotaba contra la rueda. Ahora es `from precinto import cli`.

Medido: 13 perfiles dentro de la rueda · 82 comprobaciones en verde **contra el paquete
instalado, desde fuera del repositorio** · cero intentos de red · y el flujo completo
funcionando con el checkout renombrado.

**Fuera de alcance, pendiente de decisión**: subir a PyPI. Requiere credencial y el visto
bueno de Hernán.
