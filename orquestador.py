import time
import random
import subprocess
import sys

SCRIPT_BENIGNO = "generador_benigno.py"

SCRIPTS_MALWARE = [
    "inyector_capa3_ip.py",
    "inyector_capa4_puertos.py",
    "inyector_capa4_ipat.py",
    "inyector_capa7_payload.py"
]

SCRIPT_FIREWALL = "detector_stegano_quic_mejorado3.py"

# =================================================================
# MOTOR DEL ORQUESTADOR
# =================================================================
def iniciar_simulacion():
    print("="*70)
    print(" ORQUESTADOR DE RED: SIMULACIÓN CONTINUA (BLUE TEAM vs RED TEAM)")
    print("="*70)
    
    ciclo = 1
    
    while True:
        print(f"\n[>>>] INICIANDO CICLO #{ciclo} [<<<]")
        
        # 1. Tirada de probabilidad (1 al 15)
        tirada = random.randint(1, 15)
        
        if tirada <= 11:
            script_generador = SCRIPT_BENIGNO
            tipo_trafico = "BENIGNO (Probabilidad: 11/15)"
        else:
            # Si sale 12, 13, 14 o 15, seleccionamos un malware específico
            indice_malware = tirada - 12
            script_generador = SCRIPTS_MALWARE[indice_malware]
            tipo_trafico = f"MALWARE (Probabilidad: 1/15) -> {script_generador}"
            
        print(f"[*] Seleccionado: {tipo_trafico}")
        print("[*] Ejecutando generador de tráfico...")
        
        # 2. Ejecutar el generador
        try:
            # sys.executable asegura que use el mismo intérprete de Python
            subprocess.run([sys.executable, script_generador], check=True)
        except subprocess.CalledProcessError:
            print(f"[!] Fallo al ejecutar {script_generador}. Abortando ciclo.")
            time.sleep(5)
            continue
            
        # 3. Descanso de 5 segundos para estabilizar la escritura del .pcap
        print("[*] Tráfico generado. Esperando 5 segundos para volcado completo a disco...")
        time.sleep(5)
        
        # 4. Lanzar el cortafuegos
        print("[*] Ejecutando el Firewall IDS...")
        try:
            subprocess.run([sys.executable, SCRIPT_FIREWALL], check=True)
        except subprocess.CalledProcessError:
            print("[!] Fallo al ejecutar el Firewall.")
            
        # 5. Descanso de 30 segundos
        print("\n[*] Ciclo completado. Enfriando la red durante 30 segundos...")
        for i in range(30, 0, -1):
            # Imprime un contador dinámico en la misma línea
            print(f"\r    -> Reinicio en: {i}s   ", end="")
            time.sleep(1)
            
        print("\r" + " "*30 + "\r", end="") # Limpiar la línea del contador
        ciclo += 1

if __name__ == "__main__":
    try:
        iniciar_simulacion()
    except KeyboardInterrupt:
        print("\n\n[!] Simulación detenida manualmente (Ctrl+C). Apagando orquestador.")
