# Investigación: fricción operativa en `packy-delivery` v0.4.0

Fecha: 2026-07-31
Versión evaluada: tag `v0.4.0`, commit `ba69660`
Alcance: las seis áreas de mejora del comentario del operador y los hechos
públicos observables de la entrega de Packy issue #389. Sus logs privados y su
duración end-to-end no forman parte de este repositorio.

## Método y límites

La investigación usa únicamente fuentes primarias del repositorio: código y
tests del árbol exacto de `v0.4.0`, el contrato
`workflows/packy-issue-delivery.md` y pruebas locales focalizadas. Las
referencias de línea corresponden al árbol del tag; se pueden reproducir con
`git show v0.4.0:<ruta> | nl -ba`.

Se distinguen dos clases de evidencia:

- **Estática**: el código o contrato permite afirmar qué estructura, orden o
  mensaje implementa v0.4.0.
- **Verificada**: un test ejecutado localmente ejercitó el comportamiento. Los
  tests usaron `HOME` y `XDG_CONFIG_HOME` temporales; no se invocaron GitHub ni
  efectos no locales.

| # | Afirmación | Veredicto | Confianza |
|---|---|---|---|
| 1 | La plantilla Spec omite `candidate.acceptance` | Confirmada | Alta |
| 2 | La rama se valida después del validator exhaustivo | Confirmada, con matiz | Alta |
| 3 | `row is not bound to its criterion` no localiza el error | Confirmada | Alta |
| 4 | Operaciones sobreviven a la ventana del comando y causan contención | Parcialmente confirmada | Media |
| 5 | Se protege el checkout sucio, se rechaza detached HEAD y falta `workspace prepare` | Confirmada | Alta |
| 6 | `restore-local-readiness` no explica los prefijos válidos | Confirmada | Alta |

## Hechos observables de la entrega de #389

GitHub confirma que [Packy issue #389](https://github.com/yersonargotev/packy/issues/389)
tenía siete criterios, fue cerrado por
[PR #402](https://github.com/yersonargotev/packy/pull/402), y que ese PR usó la
rama `chore/issue-389-validator-phase-timing`, obtuvo checks requeridos exitosos
sobre el HEAD `57cdad61acc9fa8be7da01e07c9fb695f1b96ca3`, se fusionó y eliminó su
rama remota. Esto respalda el tramo público PR -> CI -> merge -> cierre ->
limpieza remota.

GitHub no demuestra por sí solo la calificación interna, las revisiones
independientes, la reutilización del recibo exhaustivo, la preservación del
checkout local ni los 32m23s end-to-end. Esos puntos quedan como observación del
operador, no como hechos independientemente reproducidos en esta investigación.

## 1. Plantilla incompleta de revisión Spec

**Veredicto: confirmada.**

**Evidencia estática.** `CandidateReview` declara `Acceptance
[]AcceptanceProof` con JSON `acceptance,omitempty`; cada prueba contiene los
siete campos semánticos `positive_evidence`, `negative_evidence`,
`failure_evidence`, `mutation_evidence`, `compatibility_evidence`,
`preservation_evidence` y `migration_evidence`
(`internal/issuedelivery/types.go:379-390,471-484`). Sin embargo,
`finalizeReviewPacket` construye la respuesta candidate únicamente con las
identidades mecánicas y `Findings: []`; no inicializa `Acceptance`
(`internal/issuedelivery/review_packets.go:345-368`). Por `omitempty`, el archivo
JSON exportado no contiene `candidate.acceptance`.

Esto contrasta con la admisión: para el eje Spec con aceptación phase-owned,
`reconcileCandidatePacketResponses` llama `admitAcceptanceProofs` sobre
`review.Acceptance` y rechaza el contenido incompleto
(`internal/issuedelivery/assurance.go:464-512`). El contrato también exige que
la prueba cite la evidencia positiva, negativa/failure, mutation,
compatibility, preservation y migration requerida por cada fila
(`workflows/packy-issue-delivery.md:114-124`).

**Evidencia verificada.** Los tests focalizados de review packets pasaron, pero
no existe una aserción que exija placeholders de aceptación en la respuesta.
Por tanto verifican el contrato actual, no el comportamiento propuesto.

**Implicación.** La plantilla no cumple plenamente su promesa operativa de dejar
solo placeholders de juicio visibles. La mejora debería derivar un placeholder
por fila/obligación aplicable sin debilitar las identidades mecánicas ni el
digest del packet.

## 2. Preflight de rama después de validación exhaustiva

**Veredicto: confirmada para un candidato que aún no tiene `LocalReadiness`.**

**Evidencia estática.** Cuando `candidate.Exhaustive == nil`, el flujo ejecuta
la sesión o `m.validation.Exhaustive`, valida el resultado y registra la prueba
(`internal/issuedelivery/assurance.go:282-430`). Solo después reobserva Git y
GitHub y comprueba limpieza, HEAD/tree y `deliveryBranch`
(`internal/issuedelivery/assurance.go:432-452`). Los nombres admitidos son
`chore/issue-N-*`, `feat/issue-N-*` y `fix/issue-N-*`
(`internal/issuedelivery/assurance.go:1200-1207`). Así, un candidato limpio y
estable en `main` puede consumir la validación exhaustiva antes de bloquearse en
`local-readiness`.

El matiz es que una readiness ya persistida sí se invalida al inicio cuando la
rama o workspace dejan de coincidir (`internal/issuedelivery/assurance.go:176-195`).
Esto protege la reutilización, pero no evita el primer gasto.

**Evidencia verificada.** Pasó
`TestAdvanceRetriesFreshGateWithoutRerunningExactExhaustiveReceipt`: el fixture
cambia la rama a `main` después de la ejecución exhaustiva, observa el bloqueo
con exactamente una ejecución y luego reutiliza el recibo al restaurar la rama
(`internal/issuedelivery/assurance_test.go:1740-1759`). También pasó
`TestAdvanceReusesExactReceiptAndInvalidatesChangedCandidate`
(`internal/issuedelivery/assurance_test.go:1680-1708`).

**Implicación.** Un preflight barato de rama antes de iniciar la validación
puede evitar trabajo inútil. Debe conservar la reobservación posterior: el
preflight temprano no sustituye el gate fresco que detecta cambios durante una
operación larga.

## 3. Diagnóstico de binding sin fila ni campo

**Veredicto: confirmada.**

**Evidencia estática.** `validateCompilerQualificationBindings` recorre cada
fila y ocho celdas, pero pierde tanto el índice/identidad de la fila como el
nombre del campo al construir el error. Cualquier fallo devuelve el literal
`compiler qualification correction row is not bound to its criterion`
(`internal/issuedelivery/qualification.go:663-678`). El test asociado prueba
varios campos y valores inválidos, pero solo exige un error, no su precisión
(`internal/issuedelivery/qualification_test.go:813-850`).

El mismo validador ya define locators tipados y exige para `fixture` la gramática
`fixture/<group>/<name>` mediante una expresión regular
(`internal/issuedelivery/qualification.go:706-737`). Por tanto, el ejemplo del
comentario puede derivarse de la regla existente; lo que falta es conservar el
contexto de fila/campo y explicar la expectativa que falló.

**Evidencia verificada.** Pasaron los tests focalizados de bindings; confirman
el rechazo fail-closed, no un diagnóstico accionable.

**Implicación.** El error puede incluir `row.Identity`, el nombre JSON del campo
y la expectativa específica del locator sin cambiar la regla de admisión.

## 4. Operaciones largas, timeout y lock contention

**Veredicto: parcialmente confirmada.**

**Confirmado estática y dinámicamente.** `Advance` toma un lock exclusivo y no
bloqueante por issue; un segundo intento recibe `errIssueRunActive`
(`internal/issuedelivery/store.go:126-170`). La operación lo traduce a estado
`waiting`, razón `another Advance call is active for this issue` y metadata de
contención (`internal/issuedelivery/advance.go:146-157`). Los tests ejercitan una
operación activa real y confirman `lock-contention`/`retry-advance`
(`cmd/packy-deliver/advance_command_test.go:515-589`). Además, `watch` observa
contención sin avanzar ni escribir estado (`cmd/packy-deliver/main.go:339-350`).

**No confirmado.** El repositorio no contiene logs de #389 ni un test donde el
proceso `advance` continúe después de que su propio context/timeout haya sido
cancelado. El context sí se propaga por `Advance`, observers y validadores, y el
store lo comprueba antes de tomar el lock (`internal/issuedelivery/advance.go:16-28`;
`internal/issuedelivery/store.go:132-170`). Por tanto, la causalidad “terminó la
ventana del comando, el trabajo siguió y eso dejó contención” no queda demostrada
por estas fuentes.

El reporte expone un `run_id` persistente, timings y una firma de convergencia,
pero no existe un `operation_id` separado ni un handle observable de la
invocación activa antes de que esta responda
(`cmd/packy-deliver/advance_command.go:66-107,359-417,438-440`).

**Implicación.** La contención es recuperable y observable una vez consultada,
pero falta evidencia para escoger entre dos soluciones distintas: mejorar el
progreso de una operación legítimamente viva o corregir cancelación de
subprocesos. Antes de diseñar, conviene añadir una prueba de proceso que capture
el comportamiento al vencer/cerrar la ventana de ejecución.

## 5. Preparación del checkout de integración

**Veredicto: confirmada.**

**Evidencia estática.** El observer registra limpieza mediante `git status` y
rechaza explícitamente detached HEAD con `detached HEAD is not a delivery
workspace` (`cmd/packy-deliver/advance_local.go:86-106`). El compilador exige
workspace limpio (`internal/issuedelivery/compiler.go:253-259`). En cleanup, el
motor bloquea cambios incompatibles y no elimina worktrees no poseídos; los
tests `TestAdvancePreservesUnsafeOperatorStateAfterMerge` y
`TestAdvanceBlocksUnsafeOrUnownedWorktreeWithoutCleanup` codifican esa
protección (`internal/issuedelivery/completion_test.go:331-383`).

La superficie CLI de v0.4.0 enumera `advance`, `input-template`,
`review-packets`, `status`, `watch`, `version` y `legacy-v1`; no existe
`workspace prepare` ni equivalente (`cmd/packy-deliver/main.go:305-325`). Una
búsqueda del árbol completo del tag tampoco encuentra esa orden.

**Evidencia verificada.** Pasaron los tests focalizados de protección local,
observer y help. No se reprodujo el checkout exacto de #389 ni se creó un clon
real, así que la secuencia histórica concreta sigue fuera del alcance.

**Implicación.** Existe una brecha real entre las invariantes seguras del motor
y la preparación requerida al operador. Cualquier helper deberá conservar la
separación entre checkout del usuario y workspace administrado, y dejar
identidad/ownership suficiente para el cleanup seguro existente.

## 6. `restore-local-readiness` no explica la rama válida

**Veredicto: confirmada.**

**Evidencia estática.** Cuando una readiness existente deja de corresponder con
rama o workspace, la razón es `local readiness no longer matches the current
branch or workspace` (`internal/issuedelivery/assurance.go:176-195`). La
clasificación solo transforma el bloqueo en la acción
`restore-local-readiness` (`internal/issuedelivery/advance.go:381-382,425-449`).
Ni la razón ni la acción mencionan los patrones que el helper interno admite:
`chore/issue-N-*`, `feat/issue-N-*` o `fix/issue-N-*`
(`internal/issuedelivery/assurance.go:1200-1207`).

**Evidencia verificada.** Pasó
`TestBlockedNextActionCoversProductionTransitionPhases`, que confirma exactamente
la acción genérica para `local-readiness`
(`internal/issuedelivery/advance_test.go:521-557`). El test no exige guidance
adicional.

**Implicación.** El reporte puede mantener el `next_action` estable y añadir al
blocker una expectativa concreta de rama/workspace. Esa información debería
provenir de la misma regla que aplica el gate para evitar divergencia entre
diagnóstico y admisión.

## Conclusión

Cinco áreas están confirmadas por el código de v0.4.0 y una sexta —operaciones
que sobreviven al timeout— solo está confirmada en su efecto observable de
contención, no en su causa. La evidencia respalda priorizar plantillas
completas, preflight temprano y diagnósticos accionables. Para progreso de
operaciones largas hace falta primero una reproducción de proceso/cancelación.
Estas mejoras son de interfaz operativa y pueden plantearse sin inferir que el
motor resumible o sus invariantes deban rediseñarse.

## Verificación ejecutada

```text
env HOME=<tmp>/home XDG_CONFIG_HOME=<tmp>/config \
  go test ./internal/issuedelivery \
  -run 'TestAdvance(ReusesExactReceiptAndInvalidatesChangedCandidate|RetriesFreshGateWithoutRerunningExactExhaustiveReceipt|PreservesUnsafeOperatorStateAfterMerge|BlocksUnsafeOrUnownedWorktreeWithoutCleanup)|TestBlockedNextActionCoversProductionTransitionPhases|TestReviewPacket' \
  -count=1
ok github.com/yersonargotev/packy-delivery/internal/issuedelivery

env HOME=<tmp>/home XDG_CONFIG_HOME=<tmp>/config \
  go test ./cmd/packy-deliver \
  -run 'Test.*(Detached|LockContention|ReviewPacket|Help)' \
  -count=1
ok github.com/yersonargotev/packy-delivery/cmd/packy-deliver
```
