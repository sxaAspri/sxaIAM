# sxaiam — Fase 1: Entorno de prueba Terraform

Este directorio contiene la infraestructura del entorno sandbox de sxaiam.
Crea identidades IAM deliberadamente vulnerables en AWS para validar que
el motor de análisis de rutas de ataque detecta exactamente lo que debe detectar.

## Prerrequisitos

- Terraform >= 1.6
- Una cuenta AWS **sandbox** dedicada (nunca usar en producción)
- Credenciales con permisos para crear recursos IAM

## Uso

```bash
cd terraform/environments/sandbox

# Inicializar providers
terraform init

# Ver qué se va a crear
terraform plan

# Crear el entorno
terraform apply

# Cuando termines, limpiar todo
terraform destroy
```

## Recursos que se crean

| Recurso | Tipo | Técnica de escalación |
|---|---|---|
| `sxaiam-test-low-priv-user` | IAM User | CreatePolicyVersion swap |
| `sxaiam-test-developer-user` | IAM User | PassRole + Lambda |
| `sxaiam-test-readonly-user` | IAM User | AttachUserPolicy directo |
| `sxaiam-test-support-user` | IAM User | CreateAccessKey (credential takeover) |
| `sxaiam-test-privileged-user` | IAM User | Objetivo del credential takeover |
| `sxaiam-test-admin-role` | IAM Role | Destino de paths 2 y 3 |
| `sxaiam-test-ci-role` | IAM Role | AssumeRole chaining |

## Rutas de ataque presentes

Después de `terraform apply`, sxaiam debe detectar exactamente estas 5 rutas:

```
PATH 1 — CRITICAL
low_priv_user → iam:CreatePolicyVersion → DeploymentPolicy → AdministratorAccess

PATH 2 — HIGH
developer_user → iam:PassRole + lambda:CreateFunction → admin_role → admin

PATH 3 — HIGH
ci_role → sts:AssumeRole → admin_role → AdministratorAccess

PATH 4 — CRITICAL
readonly_user → iam:AttachUserPolicy → AdministratorAccess (directo)

PATH 5 — HIGH
support_user → iam:CreateAccessKey → privileged_user → PowerUserAccess
```

## Costo

Todos los recursos IAM son **gratuitos** en AWS.
No se crean recursos de cómputo, almacenamiento, ni red.

## Seguridad

- Estos recursos son intencionalmente inseguros — son el punto
- Nunca crear en una cuenta de producción o compartida
- `terraform destroy` elimina todos los recursos completamente
- Las access keys nunca se crean — solo los usuarios y roles
