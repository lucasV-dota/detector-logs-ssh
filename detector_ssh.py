import argparse
import re
import json
import os

parser = argparse.ArgumentParser(description="Detector ssh")
parser.add_argument("-f", "--file", help="ruta del archivo log", required=True)
parser.add_argument("-u", "--umbral", help="Cantidad minima de intentos fallidos", type=int, default=3)
parser.add_argument("-w", "--whitelist", help="IPs confiables a ignorar separadas por comas", default="")
parser.add_argument("-o", "--output", help="nombre del archivo de salida", default="reporte_ataques.json")

args = parser.parse_args()

whitelist = [ip.strip() for ip in args.whitelist.split(",") if ip.strip()]

datos_ips = {}

whitelist = set()
if args.whitelist:
    if os.path.isfile(args.whitelist):
        with open(args.whitelist, "r", encoding="utf-8") as wf:
            for linea in wf:
                ip_limpia = linea.strip()
                if ip_limpia and not ip_limpia.startswith("#"):
                    whitelist.add(ip_limpia)
    else:
        for ip in args.whitelist.split(","):
            if ip.strip():
                whitelist.add(ip.strip())
try:
    with open(args.file, "r", encoding="utf-8") as f:
        for linea in f:
            if "Failed password" in linea:
                coincidencia = re.search(r"Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)", linea)
                if coincidencia:
                    usuario = coincidencia.group(1)
                    ip = coincidencia.group(2)
                    if ip in whitelist:
                        continue

                    if ip not in datos_ips:
                        datos_ips[ip] = {
                            "intentos": 0,
                            "usuarios": []
                        }
                    datos_ips[ip]["intentos"] += 1
                    if usuario not in datos_ips[ip]["usuarios"]:
                        datos_ips[ip]["usuarios"].append(usuario)
except FileNotFoundError:
    print("No se encontro el archivo: '{args.file}'")
    exit(1)

reporte_final = {}
for ip, info in datos_ips.items():
    if info["intentos"] >= args.umbral:
        reporte_final[ip] = info

with open(args.output, "w", encoding="utf-8") as r:
    json.dump(reporte_final, r, indent=4)

print(f"[+] Reporte generado en {args.output} con {len(reporte_final)} IPs sospechosas.")

