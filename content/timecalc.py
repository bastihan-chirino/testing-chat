from datetime import datetime
import json

nombre_archivo = r"C:\Users\bcf19\Desktop\Nueva carpeta\experimento_chat\data\conversation_20260628_173907.json"

try:
    with open(nombre_archivo, "r", encoding="utf-8") as archivo:
        mensajes = json.load(archivo)

    # Mantenemos el orden original del archivo por si los IDs dictan la secuencia real
    print(f"--- Cálculo de Deltas con Módulo 5 Minutos ---\n")

    for i in range(1, len(mensajes)):
        msg_anterior = mensajes[i - 1]
        msg_actual = mensajes[i]

        t_anterior = datetime.fromisoformat(msg_anterior["timestamp"])
        t_actual = datetime.fromisoformat(msg_actual["timestamp"])

        # Delta original (puede ser negativo por el error de guardado)
        delta_original = t_actual - t_anterior
        segundos_originales = delta_original.total_seconds()

        # =====================================================================
        # SOLUCIÓN: Aplicar módulo de 5 minutos (300 segundos)
        # El módulo en Python siempre devuelve un resultado positivo,
        # lo que "repara" el salto hacia atrás en el tiempo.
        # =====================================================================
        segundos_corregidos = segundos_originales % 300

        print(
            f"De ID {msg_anterior.get('id', i)} ({msg_anterior.get('role', 'N/A')}) "
            f"a ID {msg_actual.get('id', i+1)} ({msg_actual.get('role', 'N/A')}):"
        )
        print(f"  -> Delta original: {segundos_originales:.3f} s")
        print(f"  -> Delta corregido (Módulo 5 min): {segundos_corregidos:.3f} s")
        
        # Mostrar en formato minutos:segundos si pasa de un minuto
        if segundos_corregidos >= 60:
            mins = int(segundos_corregidos // 60)
            segs = segundos_corregidos % 60
            print(f"     (Equivale a: {mins} min {segs:.2f} s)")
        print()

except FileNotFoundError:
    print(f"Error: No se encontró el archivo '{nombre_archivo}'.")
except json.JSONDecodeError:
    print(f"Error: El archivo no contiene un formato JSON válido.")
except KeyError:
    print("Error: Algunos de los elementos en el JSON no tienen 'timestamp'.")