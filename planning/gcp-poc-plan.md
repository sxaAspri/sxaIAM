# sxaiam — Prueba de concepto GCP (plan de trabajo)

> Documento de handoff. Léelo completo antes de tocar código.
> Rama de trabajo: `feature/gcp-poc`.
> **Estado (2026-11-26): Fases 0 a 5 completas; Fase 6 (validación real en GCP, opcional) pendiente.**
> Rama `feature/gcp-poc` creada desde `main` y pusheada a `origin`; PR en borrador hacia `main`.
> El bug del `__init__.py` / versión (§6) se resuelve aparte en `fix/version` desde `main`, no en esta rama.
>
> ⚠️ **Cambios sin commitear heredados de `main`**: los `.pyc` en `__pycache__/` y `debug_integration.py`
> siguen en el directorio de trabajo dentro de esta rama.
> **No incluirlos en los commits de GCP sin revisarlos.** Hacer `git add` solo de los archivos de cada
> fase (nunca `git add .` ni `git commit -a`).

---

## 0. Contexto rápido del proyecto

- sxaiam es un CLI + librería Python open source que detecta rutas de escalamiento de privilegios en AWS IAM modelándolas como grafo (networkx).
- v0.2.0 en PyPI, 14 técnicas AWS vía `TechniqueRegistry`, 191+ tests, CI en GitHub Actions.
- Validación en sandbox Terraform: sxaiam 100% de rutas detectadas, Security Hub 0%.
- Stack: Python 3.10+, boto3, Pydantic v2, networkx, Typer + Rich, Terraform, moto, ruff + mypy.

## 1. Objetivo de la PoC

Demostrar, con **solo 2 técnicas**, que la arquitectura de sxaiam se extiende a GCP
**sin modificar el motor de grafo**. El entregable más importante no son las técnicas,
sino poder afirmar: *"`PathFinder`, `EscalationPath` y los exportadores no cambiaron"*.

## 2. Qué se reutiliza y qué es nuevo

| Se reutiliza SIN cambios | Nuevo, específico de GCP |
|---|---|
| `graph/pathfinder.py` (`PathFinder`) | Modelos del snapshot GCP |
| `findings/escalation_path.py` | Mapa rol → permisos |
| `TechniqueMatch`, `Severity` (`findings/technique_base.py`) | Resolver de permisos por principal |
| `AdminNode` (`sxaiam::admin`) | Base de técnica GCP + registry GCP + 2 técnicas |
| Exportadores JSON / Markdown / GraphML | Builder del grafo GCP |

Por qué funciona: `PathFinder` solo recorre un `nx.DiGraph` buscando el nodo con
`node_type == "admin"`; las aristas llevan `technique`, `severity`, `evidence`,
`attack_steps`, `technique_match`. No sabe nada de AWS.

## 3. Las 2 técnicas

| ID | Permiso clave | Ruta | Severidad | Equivalente AWS |
|---|---|---|---|---|
| `gcp-set-iam-policy` | `resourcemanager.projects.setIamPolicy` sobre el proyecto | principal → admin (1 salto) | CRITICAL | AttachPolicy |
| `gcp-sa-impersonation` | `iam.serviceAccounts.getAccessToken` sobre una SA (rol `roles/iam.serviceAccountTokenCreator`) | principal → SA (arista hacia **cualquier** SA suplantable; el grafo decide si llega a admin) | HIGH en la arista principal→SA | AssumeRole |

Siguiente técnica natural (fuera del alcance de la PoC): `iam.serviceAccountKeys.create` (≈ CreateAccessKey).

## 4. Alcance — decisiones para mantenerlo pequeño

**Dentro:**
- Entrada por **archivo JSON** (formato de salida de `gcloud projects get-iam-policy --format=json` y `gcloud iam service-accounts get-iam-policy --format=json`). No requiere cuenta GCP para desarrollar ni testear.
- Bindings a nivel **proyecto** y a nivel **service account**.
- **Roles predefinidos** con mapa fijo (~6): `roles/owner`, `roles/editor`, `roles/viewer`, `roles/iam.serviceAccountTokenCreator`, `roles/resourcemanager.projectIamAdmin`, `roles/iam.securityAdmin`.
- Bindings con `condition`: **se ignoran y se reportan como advertencia** (mismo enfoque incremental que el resolver AWS).

**Fuera (roadmap posterior):**
- Ingesta en vivo con SDK de Google.
- Herencia organización / carpetas.
- Roles custom.
- Evaluación de condiciones IAM.
- Generalizar el núcleo (registry multi-provider, etc.).

**Arquitectura:** paquete paralelo `sxaiam/providers/gcp/` con su **propio registry**.
Cero cambios en código AWS → cero riesgo para los 191 tests existentes.

## 5. Fases

Cada fase termina con su verificación antes de pasar a la siguiente.

### Fase 0 — Fixture
- Crear `tests/fixtures/gcp/vulnerable_project.json` con un proyecto inventado:
  - usuario con `roles/resourcemanager.projectIamAdmin` → positivo técnica 1
  - usuario con `serviceAccountTokenCreator` sobre una SA que es `roles/owner` → positivo técnica 2
  - usuario con `roles/viewer` → negativo
  - SA con `serviceAccountTokenCreator` sobre una SA sin privilegios → negativo técnica 2
  - (opcional) un binding con `condition` → verificar advertencia
- Primero se define el formato del JSON; todo lo demás depende de él.

**Estado: fixture creado (2026-11-26).** Formato — un envoltorio que guarda la salida de `gcloud` **tal cual**, sin modificarla:

```json
{
  "project_id": "...",
  "project_iam_policy": { /* salida de: gcloud projects get-iam-policy <id> --format=json */ },
  "service_accounts": [
    { "email": "...", "iam_policy": { /* salida de: gcloud iam service-accounts get-iam-policy <email> --format=json */ } }
  ]
}
```

Reglas para el loader (Fase 1):
- `bindings` puede **no existir** (policy vacía real de gcloud = `{"etag": "ACAB"}`) → tratar como lista vacía.
- `condition` es opcional; `version: 3` aparece cuando hay condiciones.
- Una SA sin bindings sobre sí misma **igual se lista** (necesita su nodo en el grafo).

Resultado esperado sobre el fixture:

| Principal | Binding | Resultado esperado |
|---|---|---|
| `user:alice` | `projectIamAdmin` en el proyecto | ✅ T1 → admin (1 salto, CRITICAL) |
| `user:bob` | `tokenCreator` sobre `deployer@` (owner) | ✅ T2 → deployer → admin (2 saltos, HIGH) |
| `user:carol` | `viewer` | ❌ sin ruta |
| `serviceAccount:ci-runner@` | `tokenCreator` sobre `reader@` (solo viewer) | ❌ arista ci-runner→reader (T2), pero sin ruta a admin |
| `user:dave` | `projectIamAdmin` **con condition** | ⚠️ ignorado + advertencia, sin ruta |
| `serviceAccount:deployer@` | `owner` en el proyecto | arista `already-admin` (INFO); su ruta cruda se filtra |

> **Decidido (2026-11-26):** opción (b). La arista `deployer → AdminNode` es `already-admin` (INFO, sin
> `technique_match`); PathFinder la devuelve como ruta cruda (3 rutas) y un filtro en `providers/gcp/` la
> descarta (2 rutas). Ver Fase 4.

### Fase 1 — Modelos y loader
- `sxaiam/providers/gcp/models.py`: Pydantic `GCPBinding` (role, members, condition), `GCPServiceAccount` (email + bindings sobre la SA), `GCPSnapshot` (project_id, project_bindings, service_accounts).
- `sxaiam/providers/gcp/loader.py`: JSON → `GCPSnapshot`.
- Verificación: test que carga el fixture y cuenta bindings y SAs.

**Estado: hecho (2026-11-26).** 19 tests en `tests/unit/providers/gcp/test_loader.py`. Decisiones:
- El loader **conserva** los bindings con `condition` (`GCPBinding.is_conditional`); ignorarlos y advertir
  es trabajo del resolver (Fase 2).
- Errores de formato → `GCPSnapshotError` (subclase de `ValueError`): falta `project_id`, SA sin `email`,
  SA duplicada, binding sin `role`, JSON inválido.
- `GCPServiceAccount.member` da el identificador `serviceAccount:<email>` para cruzar con `members`.

### Fase 2 — Roles y resolver
- `sxaiam/providers/gcp/roles.py`: dict rol → lista de permisos.
- `sxaiam/providers/gcp/resolver.py`: agrupa bindings por miembro (`user:...`, `serviceAccount:...`, `group:...`) y devuelve permisos efectivos **con origen** (qué rol, si es a nivel proyecto o de qué SA). Ese origen se convierte en `evidence`.
- Verificación: tests de `can(permission, resource)` por principal.

**Estado: hecho (2026-11-26).** 35 tests en `tests/unit/providers/gcp/test_resolver.py`. Decisiones:
- Recursos con nombre real de GCP: `projects/<id>` y `projects/<id>/serviceAccounts/<email>`.
  **Herencia por prefijo:** un permiso en el proyecto cubre sus SAs (`tokenCreator` a nivel proyecto
  ⇒ puede suplantar a todas las SAs, como en GCP real).
- `roles.py` lista solo el **subconjunto de permisos relevante** de cada rol, no la definición completa.
  `editor` no tiene `setIamPolicy`. `iam.securityAdmin` sí lo tiene ⇒ también es positivo de la técnica 1.
- Miembros: `user`, `serviceAccount`, `group`, `domain`, `allUsers` y `allAuthenticatedUsers` son principales
  normales (los grupos no se expanden). `deleted:...` y los prefijos desconocidos (`principal://`, etc.) se
  ignoran con advertencia.
- Bindings condicionales: se ignoran con **una advertencia por miembro** que nombra rol y miembro.
  Los roles fuera del mapa se ignoran con advertencia.
- Toda SA del snapshot es principal aunque no tenga permisos (necesita su nodo en la Fase 4).
- Advertencias en `GCPResolver.warnings` (sin duplicados) y también en el logger.

### Fase 3 — Técnicas
- `sxaiam/providers/gcp/techniques.py`:
  - `GCPEscalationTechnique` (misma interfaz que la AWS; `check(principal, snapshot)` con tipos GCP).
  - `GCPTechniqueRegistry`.
  - Las 2 técnicas, devolviendo el **mismo `TechniqueMatch`** de AWS.
  - Técnica 1: `target_arn="sxaiam::admin"`. Técnica 2: `target_arn=<id del nodo de la SA>`.
- Verificación: tests positivo + negativo por técnica.
  - Técnica 1 también con `roles/iam.securityAdmin` (tiene `setIamPolicy`), usando un **snapshot sintético**
    en los tests de la técnica, no el fixture.

**Estado: hecho (2026-11-26).** 22 tests en `tests/unit/providers/gcp/test_techniques.py`. Decisiones:
- Id de nodo de una SA = su miembro `serviceAccount:<email>`: el mismo nodo es origen (cuando la SA actúa)
  y destino (cuando la suplantan). Es el `target_arn` de la técnica 2.
- **La técnica 2 crea arista hacia CUALQUIER SA suplantable** (HIGH), sea admin o no. El grafo decide si la
  cadena llega a admin; ese es el valor de usar PathFinder. Esto **reemplaza** el "si la SA es owner/editor"
  de §3: `ci-runner → reader` es positivo de T2 (hay arista), aunque sin ruta a admin.
- "Ya es admin" = `roles/owner` **sin condición** a nivel proyecto: `is_admin_member()` en `resolver.py`,
  para el builder de la Fase 4. Constante `ADMIN_ROLE` en `roles.py`.
- Se ignora la autoimpersonación (SA con `tokenCreator` sobre sí misma).
- `GCPTechniqueRegistry` es una clase **independiente** del `TechniqueRegistry` AWS: el `_techniques` de AWS
  es un dict de clase y heredarlo compartiría el estado. Un test verifica que el registry AWS sigue con 14.
- Agregado `GCPResolvedPrincipal.name` (`user:alice@x` → `alice@x`) para `origin_name`.

### Fase 4 — Grafo
- `sxaiam/providers/gcp/builder.py` (`GCPAttackGraph`):
  - Nodos: principales, SAs y `AdminNode`. Subclases de `IAMNode` con tipos nuevos (`gcp_user`, `gcp_service_account`).
  - Arista "ya es admin": miembro con `roles/owner` en el proyecto → AdminNode. **Solo `roles/owner`, no `editor`.**
    Atributos: `technique="already-admin"`, `severity="INFO"`, **sin `technique_match`**.
  - Aristas de técnicas, conservando la de mayor severidad (misma lógica que `_build_technique_edges`).
  - **Los principales que ya son admin (`roles/owner`) NO se evalúan contra técnicas**: solo reciben la arista
    `already-admin`. Motivo: `owner` tiene `setIamPolicy`, así que la técnica 1 dispararía para `deployer@`;
    su arista CRITICAL le ganaría a la INFO y la ruta de bob (bob → deployer → admin) saldría CRITICAL en
    vez de HIGH.
  - Filtro de rutas cuyo **origen ya es admin** (el primer nodo tiene arista `already-admin` hacia AdminNode):
    función en `sxaiam/providers/gcp/` (p. ej. `filter_already_admin(paths, graph)`). **No** se toca
    `pathfinder.py` ni los exportadores.
- Verificación (sin tocar `pathfinder.py`):
  - `PathFinder(G).find_all_paths()` crudo devuelve **3 rutas**: alice→admin, bob→deployer→admin, deployer→admin.
  - Tras el filtro quedan **2 rutas**: alice (1 salto) y bob (2 saltos).
  - La ruta de bob tiene severidad **HIGH**, no CRITICAL; y la arista `deployer → admin` es `already-admin`/INFO.
  - `ci-runner → reader` es arista del grafo pero no aparece en ninguna ruta.
  - Snapshot sintético: principal → (T2) → SA con `projectIamAdmin` → (T1) → admin. Debe salir **1 ruta de
    2 pasos con severidad CRITICAL** (la severidad de una ruta es la máxima de sus pasos: max(HIGH, CRITICAL)).

**Estado: implementada, sin commit (2026-11-26).** 22 tests en `tests/unit/providers/gcp/test_builder.py`.
Verificado: 3 rutas crudas, 2 filtradas, bob HIGH, cadena sintética CRITICAL en 2 pasos. `git diff main` no
muestra cambios en ningún `.py` fuera de `providers/` (núcleo intacto). Decisiones:
- Nodos: `GCPUserNode` (`gcp_user`), `GCPServiceAccountNode` (`gcp_service_account`) y `GCPPrincipalNode`
  para `gcp_group`, `gcp_domain`, `gcp_all_users` y `gcp_all_authenticated_users`. `node_id` = miembro IAM,
  `account_id` = project_id. Definidos en `providers/gcp/builder.py`, no en `graph/nodes.py`.
- Evidencia en las aristas como `list[str]` (no `list[dict]` como AWS): `_evidence_to_strings` y el exportador
  GraphML ya la aceptan.
- Si el `target_arn` de un match no existe como nodo, la arista se **descarta con advertencia**; no se redirige
  al AdminNode como hace `_resolve_target` en AWS.
- Filtro: `filter_already_admin(paths, graph)` + `is_already_admin_node(graph, node_id)`. Solo descarta por
  **origen**; las rutas que pasan por un admin se conservan.
- Extra cubierto por tests: cadena SA → SA → owner (3 pasos, HIGH), `allUsers` con `projectIamAdmin` (CRITICAL).

### Fase 5 — CLI
- En `sxaiam/cli.py`: subcomando tipo `sxaiam gcp scan --snapshot proyecto.json --output report.json`.
- Verificación: correrlo sobre el fixture y revisar el reporte Markdown.

**Estado: implementada, sin commit (2026-11-26).** 18 tests en `tests/unit/providers/gcp/test_cli.py` (CliRunner)
+ 3 en `test_resolver.py` para `ignored`. Reporte Markdown del fixture revisado: 2 rutas, comandos `gcloud`
y evidencia correctos. Decisiones:
- El comando vive en `sxaiam/providers/gcp/cli.py` (`gcp_app`). `sxaiam/cli.py` solo cambia en 3 líneas
  (import + `app.add_typer(gcp_app, name="gcp")`); el `scan` AWS no se toca. `console` y `_print_summary_table`
  se importan dentro del comando para evitar el import circular.
- Uso: `sxaiam gcp scan --snapshot <json> --output <archivo> [--format json|markdown] [--cutoff N]`.
  Reutiliza `JSONExporter`/`MarkdownExporter` (con `account_id=project_id`) y `_print_summary_table`.
- Resumen final: bindings ignorados **agrupados por motivo** (orden fijo: condicional, miembro eliminado,
  tipo de miembro no soportado, rol no soportado), principales que ya son admin, y aristas descartadas por el
  builder (`GCPAttackGraph.dropped_edges`) si las hay.
- Encoding: mismo criterio que `6c3bc6d` (**texto de consola solo ASCII**, todo por la consola de Rich).
  El CLI no imprime los strings en español del resolver: arma el texto desde registros estructurados
  (`GCPResolver.ignored: list[IgnoredBinding]`, motivo en `IgnoredReason`). La 'ú' rota venía del
  *last-resort handler* de `logging` (sin handlers configurados imprime WARNING en stderr): se agrega un
  `NullHandler` en `sxaiam.providers.gcp` (práctica estándar de librerías). Un test verifica que la
  advertencia cruda no aparece; sin el `NullHandler` falla.
- Los datos del snapshot se escapan con `rich.markup.escape` (un miembro con `[bold]` no se interpreta).

### Fase 6 (opcional) — Validación real
- Proyecto GCP (free trial; IAM no consume crédito; no crear VMs).
- Terraform (provider `google`) que reproduzca el fixture; exportar con `gcloud`; confirmar que el loader lee la salida real.
- Prueba manual del ataque: `gcloud auth print-access-token --impersonate-service-account=...`.
- Activar el trial solo al llegar aquí (el reloj de 90 días corre desde el registro).

## 6. Registro de puntos de refactor del núcleo

Anotar aquí todo lo que se tuvo que tocar o que estorbó del núcleo. Esta lista es el roadmap de generalización.

- [ ] `TechniqueRegistry` necesitaría atributo `provider`.
- [x] `AdminNode` tiene label fijo `"AdministratorAccess"` (AWS). **Resuelto** en
  `refactor(core): make provider labels configurable` (ver ítem de reportes más abajo).
- [ ] `TechniqueMatch` usa `origin_arn` / `target_arn` — GCP no tiene ARNs (deuda de nombres).
- [ ] `PathFinder.find_all_paths()` no distingue "ya es admin" de "escala a admin": toda arista directa a AdminNode cuenta como ruta.
  En GCP se resuelve con la arista `already-admin` + filtro por origen en `providers/gcp/`; en un núcleo
  generalizado el filtro debería vivir en `PathFinder` o en `EscalationPath`.
- [ ] Hallazgo AWS: `_ADMIN_ACTIONS` y `_ADMIN_POLICY_ARNS` (`graph/builder.py:56-64`) están definidas pero
  **no se usan** en ningún lado. El builder AWS nunca crea aristas "ya es admin", así que un principal con
  `AdministratorAccess` no aparece como admin en el grafo. Revisar si es intencional o código muerto.
- [ ] Candidata a tercera técnica GCP: `iam.serviceAccounts.setIamPolicy` sobre una SA (p. ej. con
  `roles/iam.securityAdmin`) ⇒ el atacante se otorga `tokenCreator` sobre la SA y luego la suplanta.
  Ya está en el mapa de roles; falta la técnica.
- [ ] Roadmap: miembros `principal://` / `principalSet://` (Workload/Workforce Identity Federation).
  Hoy el resolver los ignora con advertencia.
- [ ] Hallazgo AWS: `_resolve_target` (`graph/builder.py`) redirige al AdminNode cualquier `target_arn` que no
  sea un nodo. Una técnica con un objetivo mal resuelto genera así una ruta a admin falsa. GCP descarta la arista.
- [ ] Hallazgo AWS: `_build_technique_edges` envuelve cada string de evidencia en un dict con
  `action=<string completo>` y `resource="*"`, por lo que el reporte muestra `"<evidencia> on * (via policy: …)"`
  (texto redundante). Las aristas podrían guardar `list[str]` directamente, como hace GCP.
- [x] Reportes con textos AWS fijos (visible en el Markdown GCP): destino `AdministratorAccess` (label de
  `AdminNode`), cabecera `**Account:**` y pie "AWS IAM Attack Path Analysis" en `MarkdownExporter`.
  **Resuelto** en `refactor(core): make provider labels configurable`, solo etiquetas de presentación con
  defaults AWS: `AdminNode(label=...)`, `MarkdownExporter(scope_label=..., footer_tagline=...)`,
  `JSONExporter(scope_key=...)` (AWS `account_id`, GCP `project_id`, misma posición en el metadata).
  GCP pasa `"Project Owner (roles/owner)"`, `"Project"` y su propio pie. Salida AWS verificada **byte a byte**
  contra archivos de referencia generados con el código anterior (`tests/fixtures/aws/golden_report.*`,
  `eol=lf` en `.gitattributes`; test en `tests/unit/output/test_aws_report_regression.py`).
- [ ] Roadmap: campo `provider` (`"aws"` / `"gcp"`) en el `metadata` del JSON, para que los consumidores
  distingan el origen sin inferirlo de `account_id` / `project_id`. Cambia el JSON AWS (campo nuevo), así que
  requiere regenerar las referencias de forma intencional.
- [ ] `sxaiam/` no tiene `__init__.py` (es *namespace package*): `from sxaiam import __version__` falla y
  `sxaiam --version` siempre imprime el fallback `0.1.0`. El scan AWS tampoco pasa `version=` a los
  exportadores (los reportes dicen v0.1.0). El CLI GCP usa `importlib.metadata.version("sxaiam")`.
- [ ] `_print_summary_table` tiene columnas de ancho fijo (10+30+6+35): con 80 columnas (salida redirigida)
  Rich las recorta con `…` (no ASCII) y en Windows sale `CRITI�`. Afecta también al scan AWS.
- [ ] _(agregar durante el desarrollo)_

## 7. Forma de trabajo

- Primero explicar bien la idea del cambio; luego indicar por pasos qué archivos y qué partes cambiar y qué hace cada cambio (no entregar el código completo de golpe).
- Verificación explícita entre pasos.
- Si falta contexto, preguntar en vez de asumir.

## 8. Trampas conocidas del entorno (Windows)

- `python` resuelve a MSYS2 sin los paquetes: usar el Python del `.venv` del repo (o un intérprete de Windows con las dependencias instaladas), no el de MSYS2.
- CMD no soporta bloques multilínea en `python -c`: escribir scripts a archivo.
- Al copiar código desde chat, revisar artefactos tipo `[nombre](http://nombre)` en identificadores.
- Si CI no coincide con local: `git show HEAD:<ruta>` para ver lo realmente pusheado.

## 9. Pendientes de limpieza del repo (no bloquean la PoC)

- `__pycache__/*.pyc` están versionados: sacarlos del índice (`git rm -r --cached`) y agregarlos a `.gitignore`.
- Archivo suelto llamado `'` en la raíz (residuo de un comando).
- `findings.json` y `terraform/environments/sandbox/gap_report.json` sin trackear: decidir si se ignoran.
- La instalación local de `sxaiam` está desactualizada (`importlib.metadata` reporta 0.1.0; `pyproject.toml`
  dice 0.2.0): reinstalar con `pip install -e .`.
- En CI, mypy corre con `|| true` (`.github/workflows/ci.yml`): **nunca falla el build**, aunque haya errores de tipos.
