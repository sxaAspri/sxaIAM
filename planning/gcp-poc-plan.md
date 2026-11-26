# sxaiam — Prueba de concepto GCP (plan de trabajo)

> Documento de handoff. Léelo completo antes de tocar código.
> Rama de trabajo: `feature/gcp-poc`.
> Estado al crear este documento (2026-11-26): plan aprobado, **ninguna fase iniciada**.
> Rama `feature/gcp-poc` **ya creada** desde `main` (2026-11-26) y activa.
>
> ⚠️ **Cambios sin commitear heredados de `main`**: los `.pyc` en `__pycache__/`, `debug_integration.py`
> y este mismo `planning/gcp-poc-plan.md` siguen en el directorio de trabajo dentro de esta rama.
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
| `gcp-sa-impersonation` | `iam.serviceAccounts.getAccessToken` sobre una SA (rol `roles/iam.serviceAccountTokenCreator`) | principal → SA → admin (2 saltos, si la SA es owner/editor) | HIGH en la arista principal→SA | AssumeRole |

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
| `serviceAccount:ci-runner@` | `tokenCreator` sobre `reader@` (solo viewer) | ❌ arista ci-runner→reader, pero sin ruta a admin |
| `user:dave` | `projectIamAdmin` **con condition** | ⚠️ ignorado + advertencia, sin ruta |
| `serviceAccount:deployer@` | `owner` en el proyecto | arista `already-admin` (INFO); su ruta cruda se filtra |

> **Decidido (2026-11-26):** opción (b). La arista `deployer → AdminNode` es `already-admin` (INFO, sin
> `technique_match`); PathFinder la devuelve como ruta cruda (3 rutas) y un filtro en `providers/gcp/` la
> descarta (2 rutas). Ver Fase 4.

### Fase 1 — Modelos y loader
- `sxaiam/providers/gcp/models.py`: Pydantic `GCPBinding` (role, members, condition), `GCPServiceAccount` (email + bindings sobre la SA), `GCPSnapshot` (project_id, project_bindings, service_accounts).
- `sxaiam/providers/gcp/loader.py`: JSON → `GCPSnapshot`.
- Verificación: test que carga el fixture y cuenta bindings y SAs.

**Estado: hecho (2026-11-26).** 16 tests en `tests/unit/providers/gcp/test_loader.py`. Decisiones:
- El loader **conserva** los bindings con `condition` (`GCPBinding.is_conditional`); ignorarlos y advertir
  es trabajo del resolver (Fase 2).
- Errores de formato → `GCPSnapshotError` (subclase de `ValueError`): falta `project_id`, SA sin `email`,
  SA duplicada, binding sin `role`, JSON inválido.
- `GCPServiceAccount.member` da el identificador `serviceAccount:<email>` para cruzar con `members`.

### Fase 2 — Roles y resolver
- `sxaiam/providers/gcp/roles.py`: dict rol → lista de permisos.
- `sxaiam/providers/gcp/resolver.py`: agrupa bindings por miembro (`user:...`, `serviceAccount:...`, `group:...`) y devuelve permisos efectivos **con origen** (qué rol, si es a nivel proyecto o de qué SA). Ese origen se convierte en `evidence`.
- Verificación: tests de `can(permission, resource)` por principal.

### Fase 3 — Técnicas
- `sxaiam/providers/gcp/techniques.py`:
  - `GCPEscalationTechnique` (misma interfaz que la AWS; `check(principal, snapshot)` con tipos GCP).
  - `GCPTechniqueRegistry`.
  - Las 2 técnicas, devolviendo el **mismo `TechniqueMatch`** de AWS.
  - Técnica 1: `target_arn="sxaiam::admin"`. Técnica 2: `target_arn=<id del nodo de la SA>`.
- Verificación: tests positivo + negativo por técnica.

### Fase 4 — Grafo
- `sxaiam/providers/gcp/builder.py` (`GCPAttackGraph`):
  - Nodos: principales, SAs y `AdminNode`. Subclases de `IAMNode` con tipos nuevos (`gcp_user`, `gcp_service_account`).
  - Arista "ya es admin": miembro con `roles/owner` en el proyecto → AdminNode. **Solo `roles/owner`, no `editor`.**
    Atributos: `technique="already-admin"`, `severity="INFO"`, **sin `technique_match`**.
  - Aristas de técnicas, conservando la de mayor severidad (misma lógica que `_build_technique_edges`).
  - Filtro de rutas cuyo **origen ya es admin** (el primer nodo tiene arista `already-admin` hacia AdminNode):
    función en `sxaiam/providers/gcp/` (p. ej. `filter_already_admin(paths, graph)`). **No** se toca
    `pathfinder.py` ni los exportadores.
- Verificación (sin tocar `pathfinder.py`):
  - `PathFinder(G).find_all_paths()` crudo devuelve **3 rutas**: alice→admin, bob→deployer→admin, deployer→admin.
  - Tras el filtro quedan **2 rutas**: alice (1 salto) y bob (2 saltos).

### Fase 5 — CLI
- En `sxaiam/cli.py`: subcomando tipo `sxaiam gcp scan --snapshot proyecto.json --output report.json`.
- Verificación: correrlo sobre el fixture y revisar el reporte Markdown.

### Fase 6 (opcional) — Validación real
- Proyecto GCP (free trial; IAM no consume crédito; no crear VMs).
- Terraform (provider `google`) que reproduzca el fixture; exportar con `gcloud`; confirmar que el loader lee la salida real.
- Prueba manual del ataque: `gcloud auth print-access-token --impersonate-service-account=...`.
- Activar el trial solo al llegar aquí (el reloj de 90 días corre desde el registro).

## 6. Registro de puntos de refactor del núcleo

Anotar aquí todo lo que se tuvo que tocar o que estorbó del núcleo. Esta lista es el roadmap de generalización.

- [ ] `TechniqueRegistry` necesitaría atributo `provider`.
- [ ] `AdminNode` tiene label fijo `"AdministratorAccess"` (AWS).
- [ ] `TechniqueMatch` usa `origin_arn` / `target_arn` — GCP no tiene ARNs (deuda de nombres).
- [ ] `PathFinder.find_all_paths()` no distingue "ya es admin" de "escala a admin": toda arista directa a AdminNode cuenta como ruta.
  En GCP se resuelve con la arista `already-admin` + filtro por origen en `providers/gcp/`; en un núcleo
  generalizado el filtro debería vivir en `PathFinder` o en `EscalationPath`.
- [ ] Hallazgo AWS: `_ADMIN_ACTIONS` y `_ADMIN_POLICY_ARNS` (`graph/builder.py:56-64`) están definidas pero
  **no se usan** en ningún lado. El builder AWS nunca crea aristas "ya es admin", así que un principal con
  `AdministratorAccess` no aparece como admin en el grafo. Revisar si es intencional o código muerto.
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
- En CI, mypy corre con `|| true` (`.github/workflows/ci.yml`): **nunca falla el build**, aunque haya errores de tipos.
