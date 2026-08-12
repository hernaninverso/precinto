# Especificación: distribución instalable de Precinto

**Feature**: 001-empaquetar-precinto-como
**Estado**: borrador
**Fecha**: 2026-08-11

## Por qué

Hoy probar Precinto exige `git clone`. Eso descarta al lector que llega desde un
issue o desde un correo y tiene dos minutos: la fricción entre «me interesa» y «lo
corrí» es todo el embudo de este proyecto, porque la estrategia comercial entera
depende de que **un ingeniero lo pruebe sin hablar con nadie**.

El nombre `precinto` está libre en PyPI (verificado 2026-08-11).

## Alcance

Publicar Precinto como distribución instalable con `pip install precinto`, que deje
disponible el comando `precinto` en el PATH, con los perfiles incluidos.

**Fuera de alcance**: publicar efectivamente en PyPI (requiere credencial y decisión
de Hernán), versionado semántico automático, ruedas por plataforma, empaquetado del
sitio web.

## Requisitos

### RF-1 — Instalación limpia
`pip install .` en un entorno virgen deja `precinto --help` funcionando desde
**cualquier directorio**, sin el repositorio presente.

### RF-2 — Los perfiles viajan dentro
Los trece adaptadores de `perfiles/` quedan accesibles tras la instalación. Un
usuario debe poder hacer `precinto scan bundle.tar.gz --profile atlassian-dc` sin
tener el repositorio.

*Este requisito existe por una lección ya pagada en el ecosistema: `eleion-compliance-kit`
tenía `data/` fuera del paquete y todos los cargadores fallaban con `FileNotFoundError`
en el wheel, mientras los tests pasaban en instalación editable.*

### RF-3 — La dependencia mínima
Sólo `cryptography`, y sólo para firmar y verificar. El escaneo debe funcionar sin
ella si el usuario no firma.

### RF-4 — El comando declara su versión
`precinto --version` imprime la versión del paquete, tomada de los metadatos de la
distribución instalada, no de una constante duplicada en el código.

### RF-5 — El banco de pruebas es reproducible tras instalar
`precinto demo --out X` genera el paquete sintético con canarios sin necesitar el
repositorio, para que quien evalúa pueda reproducir los números publicados.

## Criterios de aceptación

| # | Criterio | Cómo se comprueba |
|---|---|---|
| CA-1 | Instala en un venv limpio | `python -m venv /tmp/v && /tmp/v/bin/pip install .` |
| CA-2 | Corre **fuera del repositorio** | `cd /tmp && /tmp/v/bin/precinto --help` |
| CA-3 | Los perfiles están presentes | `precinto scan … --profile atlassian-dc` desde `/tmp` |
| CA-4 | Cero red durante el escaneo | ejecutar con los sockets anulados; falla si algo intenta usarlos |
| CA-5 | La rueda contiene los perfiles | inspeccionar el `.whl` y contar los `.json` |
| CA-6 | La suite pasa contra lo instalado | correr los tests apuntando al paquete instalado, no al repositorio |
| CA-7 | Sin el repositorio no queda nada roto | borrar el checkout del PATH y repetir CA-2 y CA-3 |

## Invariantes que no se pueden romper

1. **Cero red** sigue siendo comprobado, no prometido.
2. El manifiesto **nunca** lleva el valor de un secreto.
3. Lista blanca cerrada en toda estructura firmada, en todos los niveles.
4. `verify` sin clave externa devuelve **NO PROBADA**, nunca «verificada».

## Riesgo principal

**Que la rueda salga rota y los tests no lo vean**, porque se prueban con instalación
editable desde el checkout. Es un fallo que ya ocurrió tres veces en este ecosistema
(`eleion-compliance-kit`, `metis`, `kanon`). Por eso CA-2 y CA-7 exigen ejecutar
**desde otro directorio, sin el repositorio**, que es la única prueba que lo detecta.
