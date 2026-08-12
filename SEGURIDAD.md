# Seguridad

## Reportar un fallo

**precinto@eleata.io**, o un asunto en el repositorio si no expone nada sensible.

No hace falta cifrar el mensaje ni adjuntar nada: **no mandes un paquete de
diagnóstico real**. Si el fallo depende de una entrada concreta, describila o mandá
un caso sintético; el generador del banco (`precinto demo`) sirve para construir uno.
Pedirte el archivo que esta herramienta existe para no mover sería contradictorio.

## Plazos

| | |
|---|---|
| Acuse de recibo | 3 días hábiles |
| Evaluación inicial y severidad | 10 días hábiles |
| Corrección de un fallo que deje salir un secreto | prioridad sobre cualquier otro trabajo |
| Publicación del arreglo | con el reporte del hallazgo en las notas de la versión |

**Lo sostiene una sola persona.** No hay guardia de 24 horas y prometerla sería
incumplirla. Si necesitás un compromiso de respuesta más rápido, va en el contrato de
la licencia comercial, no acá.

## Qué se considera un fallo de seguridad

- Un secreto o dato personal que **sale en la copia saneada** sin marcar.
- Un valor de secreto que **llega al manifiesto**, que es público por diseño.
- Cualquier escritura **fuera del directorio de salida**, o sobre el paquete original.
- Una firma inválida que el verificador dé por **válida**, en la línea de comandos o
  en el navegador.
- Una divergencia entre los dos verificadores: que uno acepte lo que el otro rechaza.
- Que la herramienta **abra una conexión de red**.
- Cualquier afirmación del sitio o del README que no se sostenga contra el código.
  Esto último cuenta como fallo de seguridad a propósito: el producto se vende sobre
  no informar de más.

## Qué NO es un fallo

- Que **no detecte** un secreto de un formato desconocido. La herramienta no promete
  encontrarlo todo, lo dice en su salida y lo declara en cada manifiesto. Es una
  mejora bienvenida, no un fallo de seguridad.
- Que un archivo se bloquee de más. Bloquear es el lado seguro del error.
- Falsos positivos que enmascaren texto inocuo, salvo que destruyan el diagnóstico.

## Verificar lo que se publica

Cada versión trae inventario de componentes en CycloneDX, hashes y procedencia
firmada. Comprobalos antes de instalar, sin confiar en nosotros:

```bash
gh attestation verify precinto-*.whl -R hernaninverso/precinto
sha256sum -c SHA256SUMS.txt
```

## Alcance de lo que la herramienta puede prometer

No promete que un paquete procesado no contenga datos sensibles. **Nadie puede
prometer eso**, y un producto que lo prometa es peor que no tener producto. Promete
que se aplicó una política identificada, con transformaciones declaradas y
limitaciones declaradas, y que eso es verificable por un tercero.

Verificar la firma contra la clave que viaja dentro del propio archivo es circular:
la herramienta devuelve **NO PROBADA** en ese caso, nunca «verificada».
