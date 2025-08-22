#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clean_logs.py
-------------
Script de limpieza/normalización de logs para entrenar modelos (Jenkins-friendly).
- Lee un archivo de texto (1 log por línea) o un CSV con columna 'message'.
- Aplica normalización robusta y guarda la salida limpia.
Uso:
  python clean_logs.py --in raw_logs.txt --out cleaned_logs.txt
  python clean_logs.py --in dataset.csv --csv --out cleaned_dataset.csv
"""

import re
import argparse
import sys
import pandas as pd
from pathlib import Path

# Compilar patrones comunes
RE_TIMESTAMP = re.compile(r'\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b')
RE_DATE_ALT = re.compile(r'\b\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2}\b')
RE_BUILDNUM = re.compile(r'(?:build\s*#\s*|#)\d+', re.IGNORECASE)
RE_PID = re.compile(r'\bPID\s*=\s*\d+\b', re.IGNORECASE)
RE_NUM = re.compile(r'\b\d{4,}\b')  # números largos (ids, puertos altos)
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_GUID = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
RE_HEX = re.compile(r'\b[0-9a-fA-F]{16,64}\b')  # hashes
RE_URL = re.compile(r'https?://\S+')
RE_EMAIL = re.compile(r'\b\S+@\S+\.\S+\b')
RE_PATH_UNIX = re.compile(r'(/[^ \t\n\r\f\v]+)+')
RE_PATH_WIN = re.compile(r'[A-Za-z]:\\[^ \t\n\r\f\v"]+')
RE_AGENT = re.compile(r'\bagent[-_ ]?[A-Za-z0-9._-]+\b', re.IGNORECASE)
RE_QUOTED = re.compile(r'"[^"\r\n]{3,}"')  # cadenas entre comillas
RE_QUOTED_SQ = re.compile(r"'[^'\r\n]{3,}'")  # comillas simples

def normalize_line(line: str) -> str:
    """Normaliza una línea de log: reemplaza valores variables por placeholders."""
    orig = line
    s = line.strip()

    # Quitar prefijos tipo [timestamp] y timestamps
    s = RE_TIMESTAMP.sub('<TIMESTAMP>', s)
    s = RE_DATE_ALT.sub('<TIMESTAMP>', s)

    # Rutas y URLs
    s = RE_URL.sub('<URL>', s)
    s = RE_PATH_WIN.sub('<WIN_PATH>', s)
    s = RE_PATH_UNIX.sub('<PATH>', s)

    # Emails e IPs
    s = RE_EMAIL.sub('<EMAIL>', s)
    s = RE_IP.sub('<IP>', s)

    # GUIDs y hashes
    s = RE_GUID.sub('<GUID>', s)
    s = RE_HEX.sub('<HEX>', s)

    # Build numbers, PIDs, números largos
    s = RE_BUILDNUM.sub('build #<N>', s)
    s = RE_PID.sub('PID=<N>', s)
    s = RE_NUM.sub('<NUM>', s)

    # Agentes
    s = RE_AGENT.sub('agent-<ID>', s)

    # Cadenas entre comillas
    s = RE_QUOTED.sub('" <STR> "', s)
    s = RE_QUOTED_SQ.sub("' <STR> '", s)

    # Normalizaciones menores
    s = re.sub(r'\s+', ' ', s).strip()
    s = s.replace('[', '').replace(']', '')  # limpia corchetes de prefijos
    return s

def process_text_file(in_path: Path, out_path: Path):
    with open(in_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [l.rstrip('\n') for l in f]
    cleaned = [normalize_line(l) for l in lines]
    with open(out_path, 'w', encoding='utf-8') as f:
        for c in cleaned:
            f.write(c + '\n')
    print(f"✅ Guardado: {out_path} ({len(cleaned)} líneas)")

def process_csv(in_path: Path, out_path: Path, column: str = 'message'):
    df = pd.read_csv(in_path)
    if column not in df.columns:
        raise SystemExit(f"La columna '{column}' no existe en el CSV.")
    df['cleaned_message'] = df[column].astype(str).map(normalize_line)
    df.to_csv(out_path, index=False)
    print(f"✅ Guardado CSV: {out_path} ({len(df)} filas)")

def main():
    ap = argparse.ArgumentParser(description='Limpieza/normalización de logs.')
    ap.add_argument('--in', dest='infile', required=True, help='Archivo de entrada (txt o csv)')
    ap.add_argument('--out', dest='outfile', required=True, help='Archivo de salida')
    ap.add_argument('--csv', action='store_true', help='Indica si la entrada es CSV (columna "message")')
    ap.add_argument('--col', dest='col', default='message', help='Columna del CSV con el texto del log')
    args = ap.parse_args()

    in_path = Path(args.infile)
    out_path = Path(args.outfile)

    if not in_path.exists():
        raise SystemExit(f"No existe el archivo de entrada: {in_path}")

    if args.csv:
        process_csv(in_path, out_path, column=args.col)
    else:
        process_text_file(in_path, out_path)

if __name__ == "__main__":
    main()
