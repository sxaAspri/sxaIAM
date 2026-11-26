"""
sxaiam.providers.gcp
====================
Prueba de concepto GCP: detección de escalamiento de privilegios a partir de
políticas IAM exportadas con gcloud. Ver planning/gcp-poc-plan.md.
"""

import logging

# Práctica estándar de librerías: sin esto, cuando la aplicación no configura
# logging, el "last resort handler" de Python imprime las advertencias en stderr
# (en Windows con encoding roto). El CLI las muestra por la consola de Rich.
logging.getLogger(__name__).addHandler(logging.NullHandler())
