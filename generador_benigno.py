from scapy.all import IP, UDP, wrpcap, Raw
import time
import os

def generar_trafico_benigno(num_paquetes=1500, archivo_salida="captura_quic.pcap"):
    print("="*60)
    print(" BLUE TEAM: GENERADOR DE TRÁFICO BASELINE (SIN MALWARE)")
    print("="*60)

    # === LIMPIEZA DE CACHÉ ===
    if os.path.exists(archivo_salida):
        os.remove(archivo_salida)
        print(f"[*] Limpiando entorno: Archivo anterior '{archivo_salida}' eliminado.")

    ip_origen = "192.168.1.50"
    ip_destino = "10.0.0.5"

    print(f"[*] Generando {num_paquetes} paquetes legítimos QUIC/UDP...")
    print(f"[*] Origen: {ip_origen} -> Destino: {ip_destino}")

    paquetes = []
    tiempo_absoluto = time.time()
    
    # ---------------------------------------------------------
    # FIJAMOS EL PUERTO: Una sesión real usa un solo puerto efímero
    # ---------------------------------------------------------
    puerto_origen = 54321 

    for i in range(num_paquetes):
        # 1. Parámetros IP: ID a 0 siguiendo el estándar para paquetes DF
        pkt_ip = IP(
            src=ip_origen,
            dst=ip_destino,
            tos=0,
            ttl=64,
            id=0, 
            flags="DF"
        )

        # 2. Capa de Transporte y Payload: Tamaño fijo simulando MTU
        pkt_udp = UDP(sport=puerto_origen, dport=443)
        payload = Raw(load=os.urandom(1200)) 

        # Ensamblaje del paquete
        pkt = pkt_ip / pkt_udp / payload

        # 3. Tiempos de llegada: Constantes (sin jitter artificial)
        tiempo_absoluto += 0.010
        pkt.time = tiempo_absoluto

        paquetes.append(pkt)

        if (i + 1) % 250 == 0:
            print(f"    -> Ensamblados {i + 1}/{num_paquetes} paquetes...")

    # Guardar en archivo PCAP
    print(f"\n[*] Escribiendo paquetes en el archivo: {archivo_salida}")
    wrpcap(archivo_salida, paquetes)
    print("="*60)
    print("[+] ¡PCAP benigno generado exitosamente (Baseline Limpio)!")
    return archivo_salida

if __name__ == "__main__":
    generar_trafico_benigno()