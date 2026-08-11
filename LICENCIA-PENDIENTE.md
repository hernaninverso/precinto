# Licencia — decisión pendiente

Este repositorio **todavía no tiene licencia asignada**. Sin un archivo `LICENSE`,
por defecto no se conceden derechos de uso a terceros: publicarlo así sería publicar
código que nadie puede usar legalmente, lo que anula el propósito de publicarlo.

## La decisión, con su precedente

El molde contractual que encaja con el modelo elegido es el de **wolfSSL**:

| Vía | Qué habilita | Qué se cobra |
|---|---|---|
| **Versión abierta recíproca** (GPLv3 / AGPLv3) | Evaluar, auditar, usar internamente, modificar | Nada |
| **Licencia comercial por producto** | Redistribuir dentro de un producto propietario | El contrato OEM |

La clave es cuál es el hecho por el que se cobra. **No es usar la herramienta: es
redistribuirla dentro de un producto cerrado.** Un fabricante que la embarque en su
producto no puede hacerlo bajo licencia recíproca sin abrir el suyo, así que compra
la comercial. Un ingeniero que la corre en su propia máquina no paga nada — y es
justamente el que la va a probar y recomendar.

Precedentes del mismo esquema: wolfSSL, Qt, MySQL en su momento, y en el mundo de la
seguridad el par motor abierto / flujo de actualizaciones pago de Greenbone.

## Alternativas y por qué no

- **Apache-2.0 / MIT**: cualquiera la embarca en su producto sin pagar. Elimina el
  único hecho imponible que tiene el modelo.
- **Solo comercial, sin versión abierta**: nadie la evalúa sin firmar antes, que es
  exactamente la fricción que este proyecto existe para evitar.
- **Source-available (BUSL y similares)**: aceptable, pero espanta a parte del
  público técnico que se quiere atraer, y complica la auditoría por parte de un
  comprador de seguridad.

## Recomendación

**AGPLv3 + excepción comercial por producto.** La AGPL cierra además el hueco de
ofrecerlo como servicio alojado sin devolver nada.

Falta la decisión del dueño del proyecto. Hasta entonces el repositorio permanece
privado.
