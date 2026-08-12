# Plan de implementación: distribución instalable de Precinto

**Feature**: 001-empaquetar-precinto-como · **Spec**: `spec.md`

## Contexto técnico

| | |
|---|---|
| Lenguaje | Python 3.9+ (funciona con el intérprete del sistema de macOS y con Homebrew) |
| Dependencia | `cryptography` (sólo firmar/verificar) |
| Construcción | `hatchling` — no necesita `setup.py` ni plantillas, y trata bien los datos del paquete |
| Formato | PEP 621 en `pyproject.toml`, sin `setup.cfg` |
| Estructura | pasar de archivos sueltos a paquete `precinto/` |

## Comprobación contra la constitución

| Principio | Cómo lo cumple este plan |
|---|---|
| **Fail-closed** | El empaquetado no cambia ninguna decisión de seguridad; los invariantes se re-verifican contra el paquete instalado, no contra el checkout |
| **Verificable, no prometido** | CA-1 a CA-7 son comandos ejecutables, no afirmaciones |
| **Sin dependencias innecesarias** | Una sola, y opcional para el camino que no firma |
| **Reversible** | El repositorio sigue funcionando con `python3 precinto.py` durante toda la migración |

## Decisiones y por qué

### D-1 — Paquete `precinto/`, no módulo suelto
Un módulo suelto no puede llevar datos asociados de forma limpia. Con paquete, los
perfiles viven en `precinto/perfiles/` y se leen con `importlib.resources`, que es la
única vía que funciona igual instalado, en editable y dentro de una rueda.

### D-2 — `importlib.resources`, nunca `__file__`
`os.path.join(os.path.dirname(__file__), "perfiles")` funciona en el checkout y falla
en una rueda comprimida. Es exactamente el fallo de `eleion-compliance-kit`.

### D-3 — Compatibilidad hacia atrás del `--profile`
Debe aceptar tanto una **ruta** (`perfiles/x.json`, como hoy) como un **nombre**
(`atlassian-dc`, que resuelve al perfil incluido). Si no, todo lo publicado —el sitio,
los informes, los correos— queda con instrucciones que dejan de funcionar.

### D-4 — La versión sale de los metadatos
`importlib.metadata.version("precinto")` con reserva a la constante del módulo cuando
se corre desde el checkout sin instalar. Una versión duplicada en dos lugares se
desincroniza el día que alguien toca uno solo.

### D-5 — `precinto demo` reemplaza a `make_canary_bundle.py`
El generador pasa a ser un subcomando para que quien evalúa reproduzca los números sin
clonar nada. El script suelto queda como envoltorio delgado.

## Fases

**F1 — Reestructurar** · mover a `precinto/`: `__init__.py`, `cli.py` (el motor actual),
`demo.py` (el generador), `perfiles/*.json`. Dejar `precinto.py` en la raíz como
envoltorio que importa del paquete, para no romper nada publicado.

**F2 — Empaquetar** · `pyproject.toml` con PEP 621, `[project.scripts] precinto =
"precinto.cli:main"`, y los perfiles declarados como datos del paquete.

**F3 — Resolver perfiles y versión** · `importlib.resources` para los perfiles con
D-3, `importlib.metadata` para la versión con D-4.

**F4 — Verificar de verdad** · construir la rueda, instalarla en un venv limpio,
ejecutar **desde `/tmp`**, correr los siete criterios de aceptación y la suite completa
contra lo instalado.

## Riesgos y mitigación

| Riesgo | Mitigación |
|---|---|
| La rueda sale sin los perfiles y los tests no lo ven | CA-5 inspecciona el `.whl`; CA-2/CA-3/CA-7 corren fuera del repositorio |
| Se rompen las instrucciones ya publicadas | D-3: `--profile` acepta ruta y nombre; el envoltorio de la raíz sobrevive |
| `importlib.resources` difiere entre 3.9 y 3.13 | usar `files()` con la reserva de `importlib_resources` sólo si hace falta; probar en ambos intérpretes |
| Se cuela una dependencia nueva sin querer | CA-1 en un venv limpio muestra el árbol instalado |
