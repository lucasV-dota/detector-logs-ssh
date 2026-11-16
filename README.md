# Detector de Ataques de Fuerza Bruta SSH (detector_ssh.py)

Herramienta de línea de comandos (CLI) desarrollada en Python para analizar registros de autenticación de Linux (auth.log), detectar patrones de fuerza bruta por SSH mediante expresiones regulares y exportar reportes estructurados en formato **JSON**.

## Características

- **Análisis con Regex (re):** Extrae direcciones IP de origen y nombres de usuario objetivo en intentos fallidos (Failed password), contemplando tanto usuarios válidos como cuentas inexistentes (invalid user).
- **Agrupación y deduplicación:** Contabiliza el total de intentos por IP y registra los usuarios únicos probados por cada atacante.
- **Umbral configurable (-u):** Filtra falsos positivos reportando únicamente las IPs que igualan o superan el límite de intentos establecido.
- **Whitelist híbrida (-w):** Permite excluir IPs confiables pasándolas directamente por consola separadas por comas o leyendo un archivo de texto con soporte para comentarios (#).
- **Exportación JSON (-o):** Genera un archivo .json indentado listo para ser consumido por APIs o sistemas SIEM.

## Requisitos

- Python 3.8 o superior (utiliza únicamente librerías estándar: argparse, json, os, re).

## Uso

- Análisis básico (umbral por defecto 3 intentos): `python3 detector_ssh.py -f auth.log`
- Personalizar umbral y salida: `python3 detector_ssh.py -f /var/log/auth.log -u 5 -o alerta_ssh.json`
- Ignorar IPs confiables: `python3 detector_ssh.py -f auth.log -w whitelist.txt`
