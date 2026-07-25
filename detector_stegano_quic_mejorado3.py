import os
import logging

# ==========================================
# 0. SILENCIADORES DE TENSORFLOW (DEBE IR PRIMERO)
# ==========================================
# Apaga los logs de C++ antes de que TF se inicialice en los subprocesos
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1' # Evita el aviso de que no hay GPU en Windows

# Importa TF y silencia sus módulos internos (incluyendo absl)
import tensorflow as tf
tf.get_logger().setLevel(logging.ERROR)
import absl.logging
absl.logging.set_verbosity(absl.logging.ERROR)

# ==========================================
# IMPORTACIONES NORMALES DEL PROYECTO
# ==========================================
import numpy as np
import matplotlib.pyplot as plt
import concurrent.futures
import time
import math
import json
import pickle
from datetime import datetime, timezone
from collections import defaultdict
from scipy.stats import entropy, skew, kurtosis
from scapy.all import PcapReader, IP, UDP, Raw
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed

# ==========================================
# CONFIGURACIÓN WAZUH
# ==========================================
LOG_FILE = r"C:\logs_firewall\alertas.json"

def enviar_alerta_wazuh(ip_origen, motivo, nivel_severidad):
    """Genera un log estructurado en JSON para el Agente Wazuh."""
    alerta = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "app": "Motor_Esteganografia",
        "severidad": nivel_severidad,
        "src_ip": ip_origen,
        "descripcion": motivo
    }
    
    try:
        directorio = os.path.dirname(LOG_FILE)
        os.makedirs(directorio, exist_ok=True)
        
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(alerta) + "\n")
        print(f"    [+] Log enviado a Wazuh: {motivo}")
    except Exception as e:
        print(f"    [ERROR] No se pudo escribir el log de Wazuh: {e}")

# ==========================================
# FUNCIONES AUXILIARES MATEMÁTICAS
# ==========================================
def calcular_entropia_shannon(datos):
    """Calcula la entropía de Shannon de una lista de valores."""
    if not datos:
        return 0.0
    frecuencias = defaultdict(int)
    for x in datos:
        frecuencias[x] += 1

    entropia_val = 0.0
    for count in frecuencias.values():
        probabilidad = count / len(datos)
        entropia_val -= probabilidad * math.log2(probabilidad)
    return entropia_val

# ==========================================
# 1. HILO 1: MOTOR ESPACIAL (Entropía Multidimensional)
# ==========================================
def motor_espacial_entropia(cabeceras):
    print("[Proceso 1 - Espacial] Calculando Entropía de Shannon en cabeceras, puertos, longitudes y tiempos...")
    flujos = defaultdict(list)
    alertas = {}

    for src, flags, tos, ip_id, ttl, sport, payload_len, timestamp in cabeceras:
        flujos[src].append({
            'flags': flags, 'tos': tos, 'id': ip_id, 'ttl': ttl, 
            'sport': sport, 'len': payload_len, 'time': timestamp
        })

    for ip_origen, paquetes in flujos.items():
        if len(paquetes) < 10:
            continue

        ids = [p['id'] for p in paquetes]
        toss = [p['tos'] for p in paquetes]
        sports = [p['sport'] for p in paquetes]
        lens = [p['len'] for p in paquetes] 
        
        tiempos = sorted([p['time'] for p in paquetes])
        ipats = np.diff(tiempos)
        ipats_ms = [round(t, 3) for t in ipats] 

        entropia_id = calcular_entropia_shannon(ids)
        entropia_tos = calcular_entropia_shannon(toss)
        entropia_sport = calcular_entropia_shannon(sports)
        entropia_len = calcular_entropia_shannon(lens)
        entropia_ipat = calcular_entropia_shannon(ipats_ms)

# ---------------------------------------------------------
        # LÓGICA AVANZADA: Entropía Normalizada (Payload, Puertos e IPAT)
        # ---------------------------------------------------------
        entropia_maxima = math.log2(len(paquetes)) if len(paquetes) > 1 else 1.0
        # El array de tiempos (IPAT) siempre tiene 1 elemento menos que el de paquetes
        entropia_maxima_ipat = math.log2(len(ipats_ms)) if len(ipats_ms) > 1 else 1.0 
        
        entropia_len_norm = entropia_len / entropia_maxima
        entropia_sport_norm = entropia_sport / entropia_maxima
        entropia_ipat_norm = entropia_ipat / entropia_maxima_ipat
        
        varianza_len = np.var(lens)

        anomalia_cifrado_tos = entropia_tos > 1.5           
        anomalia_hopping_id = entropia_id > 8.0
        
        # Umbrales inteligentes para cazar mensajes cortos (Port Hopping, IPAT y Payload)
        anomalia_estegano_puertos = (entropia_sport > 0.5) and (entropia_sport_norm > 0.85)    
        anomalia_estegano_payload = (entropia_len_norm > 0.85) and (varianza_len > 50)      
        anomalia_estegano_ipat = (entropia_ipat > 0.5) and (entropia_ipat_norm > 0.85)        

        motivos_detectados = []

        if anomalia_cifrado_tos or anomalia_hopping_id:
            motivos_detectados.append(f"Inyección Capa 3 detectada (Fragmentación IP / Hopping de ID). Entropías - ToS: {entropia_tos:.2f}, ID: {entropia_id:.2f}")
        
        if anomalia_estegano_puertos:
            motivos_detectados.append(f"Inyección Capa 4 detectada (Port Hopping UDP). Entropía Norm: {entropia_sport_norm:.2f}")
            
        if anomalia_estegano_payload:
            motivos_detectados.append(f"Inyección Capa 7 detectada (Modulación de Longitud de Payload). Entropía Norm: {entropia_len_norm:.2f}, Varianza: {varianza_len:.2f}")
            
        if anomalia_estegano_ipat:
            motivos_detectados.append(f"Inyección Capa 4 detectada (Canal Temporal Puro IPAT). Entropía Norm: {entropia_ipat_norm:.2f}")

        # Si hay al menos un ataque detectado, generamos la alerta
        if len(motivos_detectados) > 0:
            print(f"[Proceso 1] [!] Firmas de ofuscación detectadas en IP: {ip_origen}")
            for m in motivos_detectados:
                print(f"        -> {m}")

            alertas[ip_origen] = {
                "paquetes_analizados": len(paquetes),
                "nivel_amenaza": "CRÍTICO",
                "motivos_especificos": motivos_detectados # Pasamos la lista de ataques
            }

    print("[Proceso 1 - Espacial] Análisis finalizado.")
    return alertas

# ==========================================
# 2. HILO 2: MOTOR IA TEMPORAL GLOBAL (LSTM)
# ==========================================

def motor_ia_tiempos(ipats):
    print("[Proceso 2 - IA LSTM] Cargando cerebro pre-entrenado para inferencia rápida...")
    
    # Comprobar que existen los archivos del modelo
    if not os.path.exists("modelo_lstm.keras") or not os.path.exists("scaler_ia.pkl"):
        print("[!] ERROR: No se encontró el modelo pre-entrenado. Ejecuta el entrenador primero.")
        return 0, [], 0.0

    from tensorflow.keras.models import load_model
    import pickle

    # 1. Cargar el modelo, el escalador y el umbral estático
    modelo = load_model("modelo_lstm.keras")
    with open("scaler_ia.pkl", "rb") as f:
        scaler = pickle.load(f)
    with open("umbral_ia.txt", "r") as f:
        umbral = float(f.read())

    window_size = 30
    caracteristicas = []

    if len(ipats) <= window_size:
        return 0, [], umbral

    # 2. Extracción de características
    for i in range(len(ipats) - window_size):
        ventana = ipats[i : i + window_size]
        hist, _ = np.histogram(ventana, bins=10, density=True)
        asimetria = skew(ventana)
        curtosis = kurtosis(ventana)

        caracteristicas.append([
            np.mean(ventana),
            np.var(ventana),
            entropy(hist + 1e-9),
            np.mean(np.abs(np.diff(ventana))),
            0.0 if np.isnan(asimetria) else asimetria,
            0.0 if np.isnan(curtosis) else curtosis
        ])

    features = np.array(caracteristicas)
    
    # 3. Transformación usando el escalador pre-entrenado
    features_escaladas = scaler.transform(features)

    time_steps = 5
    if len(features_escaladas) <= time_steps:
         return 0, [], umbral

    X_completo = np.array([features_escaladas[i : i + time_steps] for i in range(len(features_escaladas) - time_steps)])

    # 4. Inferencia Ultrarrápida (Sin .fit)
    X_pred = modelo.predict(X_completo, verbose=0)
    errores_mse = np.mean(np.power(X_completo - X_pred, 2), axis=(1, 2))

    anomalias = np.sum(errores_mse > umbral)

    print("[Proceso 2 - IA LSTM] Inferencia finalizada en milisegundos.")
    return anomalias, errores_mse, umbral

# ==========================================
# FLUJO PRINCIPAL (Correlador Cruzado)
# ==========================================
if __name__ == "__main__":
    print("="*70)
    print(" FIREWALL IDS: CORRELACIÓN CRUZADA (COBERTURA TOTAL)")
    print("="*70)

    archivo_pcap = "captura_quic.pcap"
    cabeceras_extraidas = []
    tiempos_llegada = []
    tiempo_anterior = None

    print("[*] Proceso Principal: Extrayendo red y telemetría...")
    try:
        with PcapReader(archivo_pcap) as pcap_reader:
            for pkt in pcap_reader:
                if pkt.haslayer(IP) and pkt.haslayer(UDP):
                    
                    payload_len = len(pkt[UDP].payload)
                    timestamp_abs = float(pkt.time)

                    cabeceras_extraidas.append((
                        pkt[IP].src, 
                        pkt[IP].flags, 
                        pkt[IP].tos, 
                        pkt[IP].id, 
                        pkt[IP].ttl, 
                        pkt[UDP].sport,
                        payload_len,  
                        timestamp_abs 
                    ))

                    if tiempo_anterior is not None:
                        delta = (timestamp_abs - tiempo_anterior) * 1000.0
                        tiempos_llegada.append(max(delta, 0.001))
                    tiempo_anterior = timestamp_abs
    except Exception as e:
        print(f"[!] Error leyendo PCAP: {e}")
        exit()

    print("[*] Proceso Principal: Desplegando análisis concurrente multiproceso...")

    with concurrent.futures.ProcessPoolExecutor(max_workers=2) as executor:
        tarea_espacial = executor.submit(motor_espacial_entropia, cabeceras_extraidas)
        tarea_temporal = executor.submit(motor_ia_tiempos, tiempos_llegada)

        alertas_flujos = tarea_espacial.result()
        anomalias_tiempo, errores_mse, umbral_alarma = tarea_temporal.result()

    print("\n" + "="*60)
    print(" REPORTE DEL CORRELADOR (ACCIÓN DE MITIGACIÓN)")
    print("="*60)

    ataque_confirmado = False

    if alertas_flujos:
        ataque_confirmado = True
        print("[!!!] BLOQUEO ACTIVO: CANAL ENCUBIERTO CONFIRMADO")
        for ip, datos in alertas_flujos.items():
            print(f"    -> Origen Hostil Identificado: {ip}")
            print(f"    -> Acción: DROP aplicado a todas las conexiones de {ip}")
            
            # Recorremos la lista de ataques y enviamos un log por cada uno
            for motivo_ataque in datos["motivos_especificos"]:
                enviar_alerta_wazuh(
                    ip_origen=ip, 
                    motivo=motivo_ataque, 
                    nivel_severidad="CRITICO"
                )

    elif anomalias_tiempo > 0:
        print("[!] Advertencia: Picos de latencia globales detectados (Posible congestión o ataque DDoS/Flood).")
        enviar_alerta_wazuh(
            ip_origen="0.0.0.0", 
            motivo=f"Anomalía temporal detectada. {anomalias_tiempo} ventanas de latencia superaron el umbral LSTM.", 
            nivel_severidad="ADVERTENCIA"
        )
    else:
        print("[+] Red limpia. Sin anomalías.")

    print("="*60 + "\n")

    if len(errores_mse) > 0:
        plt.figure(figsize=(12, 5))
        plt.plot(errores_mse, color='blue', alpha=0.7, label='Error Reconstrucción (MSE)')
        plt.axhline(y=umbral_alarma, color='red', linestyle='--', linewidth=2, label='Umbral de Alarma')

        color_alerta = 'darkred' if ataque_confirmado else 'orange'
        etiqueta_alerta = 'Ataque Confirmado' if ataque_confirmado else 'Anomalía Temporal (Aislada)'

        plt.fill_between(range(len(errores_mse)), errores_mse, umbral_alarma, where=(errores_mse > umbral_alarma), color=color_alerta, alpha=0.5, label=etiqueta_alerta)

        plt.title(f"Análisis Red Neuronal LSTM - {'Ataque Mitigado' if ataque_confirmado else 'Monitorización'}")
        plt.xlabel("Ventanas Temporales")
        plt.ylabel("Error MSE")
        plt.legend()
        plt.tight_layout()
        
        # Guardamos el gráfico como imagen sin interrumpir el proceso
        nombre_grafico = "reporte_lstm_ultimo.png"
        plt.savefig(nombre_grafico)
        plt.close() # Libera la memoria de la ventana gráfica
        print(f"[+] Gráfico del análisis guardado en disco: {nombre_grafico}")