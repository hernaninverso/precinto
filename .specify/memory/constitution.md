# Constitución eleata — base para `/speckit.constitution`

> Esta es la constitución base de los proyectos de Hernán. Cuando corras `/speckit.constitution` en un repo, partí de acá y agregá solo lo específico del repo (stack, dominio, compliance particular). NO copies el template vacío de spec-kit.
> Deriva de `~/.claude/AGENTS.md` (constitución operativa) — si AGENTS.md cambia, esto también.

## Core Principles

### I. Revenue-first prioritization (NON-NEGOTIABLE)
Jerarquía de decisión: **Revenue > Speed > Positioning > Reliability > Knowledge**. Ante un trade-off, gana el de más arriba. Excepción: cuando algo amenaza producción LIVE o pérdida de datos, Reliability sube a tope ("reliability > revenue" para reparar/observar antes de desbloquear pago). Optionality NO es un pilar.

### II. No implementar sin "dale"
Todo plan se presenta primero y se espera aprobación explícita ("dale" o equivalente) antes de tocar código. Excepción: fixes triviales / one-off que Hernán marca como tales. Para features no triviales: spec → plan → tasks → aprobación → implement (ver `~/templates/planner-matrix.md`).

### III. e2e antes de "funciona" (NON-NEGOTIABLE)
NUNCA marcar algo como "funciona" / "está listo" sin verificación end-to-end real (curl al endpoint, query a la DB, recorrido del flujo). Si los tests fallan, decirlo con el output. Si un paso se saltó, decirlo. Sin inflar logros.

### IV. Test + lint + typecheck antes de handoff
Antes de entregar: lint (ruff) + typecheck (mypy) + tests + smoke E2E. No regresar tests existentes. Configs estándar en `~/.claude/rules/gotchas-release-readiness.md`.

### V. Conventional Commits + commits selectivos
Conventional Commits. Co-Authored-By al modelo correspondiente. NUNCA `--no-verify`, `--force` a main, `reset --hard` sin pedido explícito. **Selective `git add`** (NO `git add -A`) + grep `\.env|secret|key|password|token` antes de commit. NUNCA crear repos públicos sin confirmación (default = privado).

### VI. Stop conditions
Parar y preguntar si: (a) aparece una dependencia que requiere cambios fuera del scope pedido; (b) un pre-commit/CI/test falla → diagnosticar root cause, NO bypass; (c) gasto API > $2 en una operación; (d) acción destructiva o que afecta producción LIVE; (e) cambio a auth/MFA/passwords/security controls — JAMÁS sin autorización explícita (afecta compliance score).

### VII. Captura de conocimiento (auto-learning, mandatory)
Después de fixear un bug o descubrir un gotcha: appendearlo a `~/.claude/rules/gotchas-*.md` (formato symptom → fix, una línea, sin duplicar). Después de cerrar una FASE/feature: actualizar el topic file de memoria correspondiente (two-step: topic file primero, índice `MEMORY.md` después). Reusar libs existentes (`~/.claude/rules/reusable-libs.md`) antes de construir.

## Additional Constraints
- Multi-tenant: el `empresa_id` / `tenant_id` del JWT manda (no el body). Aplicar a todo router que reciba ese campo. RLS donde corresponda.
- FastAPI: routers montados ANTES del catch-all `@app.get('/{path:path}')`. Imports circulares → import dentro de funciones.
- Secrets: nunca hardcoded en código ni en `settings.json`. Env vars / Keychain / 1Password. `settings.json` NO expande `${VAR}` → wrapper script (ver `SECRETS_MIGRATION.md`).
- Server LIVE: `ssh hernan@100.67.255.59` (Tailscale, pre-autorizado). Restart de servicios solo con confirmación. Detalle en `~/.claude/rules/quiron-server.md`.

## Development Workflow
- Tareas no triviales: Spec-Driven Development (spec.md → plan.md → tasks.md → implement). Ver `~/templates/planner-matrix.md` para cuándo usar spec-kit completo vs lite vs nada.
- Planes de alto-stakes: review con council (`/plan-with-council` — Codex tie-break + frontier free, ~10 rondas a convergencia).
- Cierre de sesión: `/sprint-report` (Done / Bugs fixeados / Acciones humanas P0-P2 / Pendiente / stats).
- Agentes paralelos: cada uno en su `git worktree add` (worktree compartido se pisa commits).

## Governance
Esta constitución supera prácticas ad-hoc. Enmiendas: documentar el cambio acá y en `AGENTS.md`. Toda PR/review verifica cumplimiento. La complejidad se justifica o se saca (YAGNI). Ningún tool/skill/hook nuevo si no reemplaza un paso manual Y ahorra tiempo esta semana o desbloquea un deal.

**Version**: 1.0.0 | **Ratified**: 2026-05-12 | **Last Amended**: 2026-05-12
