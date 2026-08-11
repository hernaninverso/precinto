# Licencia comercial de Precinto

Precinto se publica bajo **AGPL-3.0** (ver `LICENSE`). Este documento describe cuándo
esa licencia **no** alcanza y hay que adquirir una comercial.

## Cuándo la AGPL te sirve y no tenés que pagar nada

- Correrlo en tu propia infraestructura, para tus propios paquetes de diagnóstico.
- Auditarlo, modificarlo, integrarlo con tus herramientas internas.
- Usarlo en una consultoría, para el paquete de tu cliente.
- Redistribuirlo, siempre que lo hagas también bajo AGPL-3.0.

**Si sos ingeniero y querés probarlo: no necesitás hablar con nadie ni pedir permiso.**
Ese es el punto.

## Cuándo hace falta una licencia comercial

Cuando **redistribuís Precinto dentro de un producto propietario**, o lo ofrecés como
parte de un servicio en red, y no querés licenciar tu producto bajo AGPL-3.0.

El caso típico es un fabricante de software autoalojado que quiere que su propio
generador de paquetes de diagnóstico llame a Precinto antes de que el archivo salga de
la máquina del cliente. Ese fabricante está distribuyendo Precinto dentro de su
producto: necesita la licencia comercial.

**El hecho por el que se cobra no es usar la herramienta. Es redistribuirla dentro de
un producto cerrado.** El ingeniero que la corre en su máquina nunca paga; el
fabricante que la embarca en su producto, sí.

## Por qué AGPL y no permisiva

Con Apache-2.0 o MIT, cualquier fabricante embarca Precinto en su producto sin pagar y
sin devolver nada: desaparece el único hecho imponible que tiene este proyecto. Con una
licencia solo comercial, nadie puede evaluarlo sin firmar antes — que es exactamente la
fricción que este proyecto existe para eliminar.

La AGPL, además, cierra el hueco de ofrecerlo como servicio alojado sin devolver las
modificaciones. Precinto está diseñado para correr del lado del cliente; alguien que lo
convierta en un servicio en la nube estaría contradiciendo su premisa, y la AGPL hace
que al menos tenga que hacerlo a la vista.

Es el esquema de wolfSSL, de Qt y, en seguridad, del par motor abierto / actualizaciones
pagas de Greenbone. Está probado durante décadas y los departamentos de compras
empresariales ya saben leerlo.

## Qué incluye la licencia comercial

- Derecho de redistribución dentro de un producto identificado, sin obligación de
  licenciar ese producto bajo AGPL.
- Distribución ilimitada aguas abajo: se licencia **por producto**, no por instalación
  ni por endpoint. No hay telemetría, ni conteo remoto, ni nada que llame a casa.
- Paquetes de actualización firmados, apropiados para entornos sin conexión.
- Soporte de tercer nivel sobre el componente, en horario laboral. El primer y segundo
  nivel con el cliente final quedan del lado del fabricante.
- Un perfil calibrado para el formato de paquete de ese producto.

## Qué **no** incluye, dicho antes de que lo preguntes

- **No hay garantía de que no queden datos sensibles.** Nadie puede darla, y una
  licencia que la prometiera sería una licencia que miente. Precinto acredita un
  proceso aplicado con sus limitaciones declaradas; no certifica una ausencia.
- **No hay conformidad regulatoria automática.** Que el procesamiento sea local ayuda
  con la minimización de datos, pero no convierte a nadie en conforme con ninguna
  norma por el solo hecho de instalarlo.
- **No hay guardia 24×7** mientras el proyecto lo sostenga una sola persona.
  Prometerla sería incumplirla.

## Continuidad

Si el proyecto deja de mantenerse, la versión AGPL sigue disponible y es completa: no
hay funciones recortadas en la versión abierta, ni un motor distinto. Un fabricante que
haya licenciado la versión comercial conserva el derecho sobre la versión entregada,
y el software **no deja de funcionar** si no se renueva. La renovación habilita
versiones nuevas, reglas nuevas y soporte — nunca es un interruptor sobre lo ya
instalado, porque poner un interruptor comercial dentro de infraestructura desconectada
sería exactamente el tipo de cosa que este producto existe para no hacer.

## Contacto

Para una licencia comercial: **precinto@eleata.io**, o abrir un asunto en
<https://github.com/hernaninverso/precinto/issues>.

Si escribís porque tu producto genera paquetes de diagnóstico, decime cuál es y te mando el
perfil de partida para tu formato. **No hace falta que mandes ningún paquete** — de hecho,
preferiría que no lo hicieras: el sentido de esta herramienta es que tus datos no salgan de
tu máquina, y eso me incluye a mí.
