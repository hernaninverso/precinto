# Mensajes listos para enviar — los envía Hernán

Estos dos mensajes están redactados, verificados y listos. **No los envío yo**: son
comunicación pública en nombre de Hernán, en el foro de otra empresa, y una vez
publicados quedan en el historial aunque se borren. Esa parte le corresponde.

Todo lo demás está hecho: los datos verificados, el texto adaptado a cada caso, y el
enlace real ya insertado.

---

## 1 · Grafana — `grafana/alloy` issue #500

**Verificado el 2026-08-11**: estado `open`, **abierto el 23 de enero de 2023**,
**cero comentarios** en más de tres años. El mismo pedido está también en
`grafana/agent` #2796, igualmente abierto.

Publicar como comentario en <https://github.com/grafana/alloy/issues/500>.

```text
This has been open for three years with no replies, so: I built a working
implementation and I'm not selling anything in this message — I'd rather it be
useful to whoever picks the ticket up.

precinto (AGPL-3.0) takes a support bundle and produces two things: a sanitized
copy, and an Ed25519-signed manifest describing what was transformed and what it
could NOT inspect. Local only, read-only, no network access at all, no ML.

  pip install precinto
  precinto scan bundle.tar.gz --profile grafana --out out --sign key.pem

There's a starting profile for Grafana/Alloy bundles in the repo. Not calibrated
against real bundles — I don't have any, and I'd rather say so than pretend.

Three design decisions that are relevant to this specific ticket:

- Verifying the signature against the key embedded in the file itself is
  circular, so it returns NOT PROVEN, never "verified". Proving provenance needs
  the public key obtained through an independent channel.
- The signed envelope uses a closed whitelist at every level — root, sub-blocks,
  every list item. One undeclared field invalidates it, because a visible field
  the signature doesn't cover is a channel for text that looks verified and
  isn't.
- The manifest never contains the value of a secret, and neither do the file
  names inside the sanitized copy: a file called ghp_<token>.log would otherwise
  carry the secret out in its name with perfectly clean contents.

It also never claims "no secrets remain" — nobody can claim that. It claims
"processed under policy X version Y, with these transformations and these stated
limitations", which is a thing a security team can actually verify.

Browser verifier (runs entirely client-side, nothing uploaded):
https://precinto.eleata.io/verificar
Code: https://github.com/hernaninverso/precinto

If it's useful, take it — the license allows it and I'd rather it get used than
sit here. If the approach is wrong, I'd genuinely like to know where.
```

---

## 2 · Atlassian — `JRASERVER-78759` (y `CONFSERVER-99617`)

**Verificado el 2026-08-11**: estado **Gathering Interest**, creado el
**21 de abril de 2025**. El texto del pedido dice, literal, que la revisión manual es
*«labor-intensive, time-consuming, and prone to human error»*.

Publicar en <https://jira.atlassian.com/browse/JRASERVER-78759>. Requiere sesión
Atlassian, así que no hay comando: es entrar y pegar.

```text
This ticket says the manual review is "labor-intensive, time-consuming, and prone
to human error". I agree, so I built a working implementation of exactly what it
asks for, and I'm posting it here rather than selling it to anyone.

precinto (AGPL-3.0) takes a support.zip and produces a sanitized copy plus a
signed manifest of what was transformed and what could NOT be inspected. Local
only, read-only, no network access.

  pip install precinto
  precinto scan support.zip --profile atlassian-dc --out out

The atlassian-dc profile is a starting point built from the public docs for Jira,
Confluence and Bitbucket Data Center. It is NOT calibrated against real support
zips — I don't have any, and calibrating it properly needs someone who does.

Two things worth knowing given what this ticket is about:

- It never claims "no sensitive data remains". Nobody can claim that, and a tool
  that does is worse than no tool. It claims "processed under policy X version Y,
  with these transformations and these stated limitations" — verifiable by the
  customer's own security team, offline.
- Your own KB already says that after running the anonymisation script one should
  "still check for sensitive data that the script might not have removed". That
  gap — between what was done and what can be shown to have been done — is what
  the signed manifest is for.

Code: https://github.com/hernaninverso/precinto
Browser verifier: https://precinto.eleata.io/verificar

Happy to adapt the profile if anyone from the team wants to point me at what a
real support.zip contains.
```

---

## Por qué la variante «tu propio ticket» y no un correo en frío

La audiencia de un pedido abierto **ya se autoseleccionó**: quien está suscrito declaró
interés por escrito. Y llegar con una implementación a un ticket que lleva tres años
sin una sola respuesta construye la reputación que, en el informe de agosto, aparecía
como el único sustituto viable de un vendedor.

Ambos mensajes admiten de antemano que el perfil no está calibrado. Es cierto, y
decirlo primero evita la única objeción que hundiría la conversación entera.
