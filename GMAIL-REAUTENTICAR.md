# Re-autenticar el Gmail del servidor — lo tiene que hacer Hernán

El consentimiento de OAuth exige una persona frente a un navegador. Todo lo demás está
verificado y preparado.

## Estado medido (2026-08-11)

| | |
|---|---|
| Credencial | `~/.gmail-mcp/credentials.json` en Quirón, del 6-jun-2026 |
| **Venció** | **7 de junio de 2026, 01:06 UTC — hace 65 días** |
| Ámbitos actuales | `gmail.modify` + `gmail.settings.basic` |
| Síntoma | el MCP responde `Error: invalid_grant` |

**Corrección de un dato que circulaba mal**: la memoria decía «~13-jun». El token venció
el **7 de junio**, y el último triaje real que salió es del **12 de junio**. Son fechas
distintas y conviene no confundirlas.

## El hallazgo que cambia la recomendación

La recomendación que veníamos repitiendo era «al re-autenticar, pedí sólo
`gmail.readonly`». **Con este MCP no se puede**: `@gongrzhe/server-gmail-autoauth-mcp`
tiene los ámbitos **cableados en el código** —`gmail.modify` y `gmail.settings.basic`—
y no expone forma de elegirlos.

Eso importa porque `gmail.modify` **permite enviar correo y modificar la bandeja**. Para
un canal que sólo tiene que *leer*, es más permiso del necesario, y es el permiso que un
correo malicioso intentaría aprovechar si alguna vez lograra influir en el agente.

### Las tres salidas, en orden de preferencia

1. **Un lector propio de sólo lectura.** El propio `canal_correo.py` de Hermes dice que
   «el lector es intercambiable». Leer no-leídos de las últimas 24 horas con
   `gmail.readonly` son unas cien líneas contra la API REST. Es la única opción que deja
   el permiso donde corresponde, y se construye con spec-kit como todo lo demás.
2. **Instalar el MCP local (no por `npx`) y parchear los ámbitos.** Funciona, pero cada
   actualización lo revierte y `npx -y` vuelve a bajar la versión del registro.
3. **Re-autenticar tal cual, con `gmail.modify`.** Devuelve el triaje hoy mismo, con más
   permiso del necesario. Aceptable como puente si hace falta ya, no como destino.

## Procedimiento para la opción 3 (el puente)

> `<SERVIDOR>` es la dirección del servidor en la red privada. No va escrita acá:
> este repositorio es público y la dirección de una máquina interna no tiene por qué
> estar en él.

Correr **en la Mac**, porque abre un navegador:

```bash
ssh -L 3000:localhost:3000 hernan@<SERVIDOR>
# y dentro de la sesión:
npx -y @gongrzhe/server-gmail-autoauth-mcp auth
```

El túnel de la línea 1 es lo que hace que el redirect de OAuth —que apunta a
`localhost:3000` del servidor— se pueda completar desde el navegador de la Mac.

Al terminar, comprobar que de verdad lee, en vez de suponerlo:

```bash
ssh hernan@<SERVIDOR> 'cd ~/quiron-jobs/scripts && \
  sed "s#https://api.telegram.org#http://127.0.0.1:9#g" qjob-triage-emails.sh > /tmp/t.sh && \
  QJOBS_HOME=$(mktemp -d) QJOBS_SHADOW=1 bash /tmp/t.sh; echo "exit=$?"'
```

- `exit=0` con un resumen o con «sin no-leídos **CONFIRMADO por el servidor**» → funciona.
- `exit=1` con «NO SE PUDO LEER EL CORREO» → la credencial sigue mal.

Esa distinción existe desde hoy: antes el job informaba «sin emails importantes nuevos»
procesando la cadena `Error: invalid_grant` como si fuera una lista de correos, y salía
en verde. Llevaba así desde el 12 de junio.

## Lo que NO depende de esto

El canal de avisos de **Precinto** no toca Gmail: el Worker de Cloudflare avisa por
Telegram desde el borde, donde el correo pasa igual, y reenvía al buzón sin credencial
de por medio. Si un cliente escribe a `precinto@eleata.io` hoy, el aviso llega aunque el
Gmail del servidor siga muerto.
