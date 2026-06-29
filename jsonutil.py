import os
import json
import re
import csv
from collections import Counter

# --- CONFIGURATION ---
# Change this to the path of your folder containing the JSON files
FOLDER_PATH = './data'
OUTPUT_CSV_NAME = 'pii_analysis_report.csv'
# ---------------------

def analizar_eventos_pii_csv():
    pii_blocked_count = 0
    retry_after_pii_count = 0
    file_count = 0
    categorias_counter = Counter()

    try:
        files = os.listdir(FOLDER_PATH)
    except FileNotFoundError:
        print(f"🔴 Error: The folder '{FOLDER_PATH}' does not exist. Please check the path.")
        return

    for file in files:
        if file.lower().endswith('.json'):
            file_count += 1
            file_path = os.path.join(FOLDER_PATH, file)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    # 1. Count events (checking both spelling variations just in case)
                    contenido_raw = f.read().lower()
                    pii_blocked_count += (contenido_raw.count("pii_blocked") + contenido_raw.count("pii_bloqued"))
                    retry_after_pii_count += contenido_raw.count("retry_after_pii")
                    
                    # 2. Parse JSON for categories
                    f.seek(0)
                    data = json.load(f)
                    buscar_y_extraer_summary(data, categorias_counter)
                    
            except json.JSONDecodeError as parse_err:
                print(f"❌ JSON syntax error in file {file}: {parse_err}")
            except Exception as e:
                print(f"❌ Error reading file {file}: {e}")

    # --- GENERATING THE CSV FILE ---
    try:
        with open(OUTPUT_CSV_NAME, mode='w', encoding='utf-8', newline='') as csv_file:
            writer = csv.writer(csv_file)
            
            # Section 1: Global metrics
            writer.writerow(['=== METRICAS GLOBALES ==='])
            writer.writerow(['Metrica', 'Total'])
            writer.writerow(['Archivos JSON Analizados', file_count])
            writer.writerow(['Mensajes Bloqueados (pii_blocked)', pii_blocked_count])
            writer.writerow(['Reintentos (retry_after_pii)', retry_after_pii_count])
            writer.writerow([]) # Empty spacer row
            
            # Section 2: Category Breakdown
            writer.writerow(['=== DESGLOSE DE CATEGORIAS PII ==='])
            writer.writerow(['Categoria PII', 'Frecuencia (Veces Detectada)'])
            
            if categorias_counter:
                for cat, total in categorias_counter.most_common():
                    writer.writerow([cat, total])
            else:
                writer.writerow(['No se detectaron categorias', 0])
                
        print(f"\n✅ Report successfully generated: '{OUTPUT_CSV_NAME}'")
        print(f"📊 Scanned {file_count} files. Total pii_blocked: {pii_blocked_count}, Total retry_after_pii: {retry_after_pii_count}\n")
        
    except Exception as e:
        print(f"🔴 Error writing CSV file: {e}")

def buscar_y_extraer_summary(obj, counter):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() == "summary" and isinstance(v, str):
                match_bloque = re.search(r'datos sensibles:\s*([^.]+)', v)
                if match_bloque:
                    texto_categorias = match_bloque.group(1)
                    encontradas = re.findall(r'\b[A-Z_]{3,}\b', texto_categorias)
                    counter.update(encontradas)
            else:
                buscar_y_extraer_summary(v, counter)
    elif isinstance(obj, list):
        for item in obj:
            buscar_y_extraer_summary(item, counter)

if __name__ == "__main__":
    analizar_eventos_pii_csv()