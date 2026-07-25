from scapy.all import IP, UDP, wrpcap, Raw, rdpcap
import numpy as np
import time
import random
import hashlib
import os

CLAVE_PRECOMPARTIDA = b"RedTeam2026Secret"
SEMILLA_SALTO = int(time.time())
PAQUETES_CHAFF = 500
IP_ESTEGANO = "192.168.1.99"
IP_DESTINO = "10.0.0.5"

def vernam_cifrar(mensaje_bytes, clave):
    clave_extendida = b""
    while len(clave_extendida) < len(mensaje_bytes):
        clave_extendida += hashlib.sha256(clave + clave_extendida).digest()
    return bytes([m ^ k for m, k in zip(mensaje_bytes, clave_extendida)])

def generador_bases_ip(seed, n_bases):
    random.seed(seed)
    bases = []
    rango = 55000 // n_bases
    for i in range(n_bases):
        bases.append(5000 + i * rango + random.randint(0, rango - 10))
    return bases

def generar_pcap():
    print("="*60)
    print(" GENERADOR PCAP: CANAL ENCUBIERTO (CAPA 4 - IPAT LIMPIO)")
    print("="*60)
    mensaje_plano = "PolHackedYou:)"
    mensaje_cifrado = vernam_cifrar(mensaje_plano.encode(), CLAVE_PRECOMPARTIDA)

    archivo = "captura_quic.pcap"
    if os.path.exists(archivo):
        os.remove(archivo)

    ip_normal = "192.168.1.50"
    n_reales = len(mensaje_cifrado)
    bases = generador_bases_ip(SEMILLA_SALTO, n_reales)

    pos_reales = sorted(random.sample(range(1000, 9000), n_reales))
    pos_chaff = set()
    for pos in pos_reales:
        for _ in range(PAQUETES_CHAFF):
            off = random.randint(-300, 300)
            np_pos = max(0, min(pos + off, 9999))
            if np_pos not in pos_reales:
                pos_chaff.add(np_pos)

    todas = sorted(set(pos_reales) | pos_chaff)
    mapa = {p: (i, mensaje_cifrado[i], bases[i]) for i, p in enumerate(pos_reales)}

    pkts = []
    t = time.time()
    puerto_origen_fijo = random.randint(49152, 65535)

    for pos in todas:
        if pos in mapa:
            idx, byte_val, base_id = mapa[pos]
            retraso = 0.050 + (byte_val * 0.001)
            t += retraso

            pkt = IP(src=IP_ESTEGANO, dst=IP_DESTINO, tos=0, ttl=64, id=base_id, flags="DF") / \
                  UDP(sport=puerto_origen_fijo, dport=443) / Raw(os.urandom(1200))
        else:
            # Ruido con retraso constante y estático
            retraso = 0.010
            t += retraso

            pkt = IP(src=ip_normal, dst=IP_DESTINO, tos=0, ttl=64, id=0, flags="DF") / \
                  UDP(sport=puerto_origen_fijo, dport=443) / Raw(os.urandom(1200))

        pkt.time = t
        pkts.append(pkt)

    wrpcap(archivo, pkts)
    print(f"[+] PCAP generado: {archivo}")
    return archivo, mensaje_plano, bases

def decodificar(archivo, clave, bases, ip_esperada):
    print("\n" + "="*60)
    print(" DECODIFICADOR FORENSE (CAPA 4 IPAT)")
    print("="*60)

    pkts = rdpcap(archivo)
    resultados = {}
    tiempo_anterior = None

    for pkt in pkts:
        if IP not in pkt or UDP not in pkt:
            continue

        tiempo_actual = float(pkt.time)
        ipat = tiempo_actual - tiempo_anterior if tiempo_anterior is not None else 0.0
        tiempo_anterior = tiempo_actual

        ip = pkt[IP]
        if ip.src != ip_esperada or ip.ttl != 64:
            continue

        for i, base in enumerate(bases):
            if ip.id == base:
                byte_val = int(round((ipat - 0.050) / 0.001))
                if 0 <= byte_val <= 255:
                    resultados[i] = byte_val
                break

    if not resultados:
        return "<ninguno>", b""

    indices = sorted(resultados.keys())
    bytes_cif = bytes([resultados[i] for i in indices])
    descif = vernam_cifrar(bytes_cif, clave)
    try:
        return descif.decode('utf-8'), bytes_cif
    except:
        return f"<hex:{descif.hex()}>", bytes_cif

if __name__ == "__main__":
    archivo, original, bases = generar_pcap()
    recuperado, _ = decodificar(archivo, CLAVE_PRECOMPARTIDA, bases, IP_ESTEGANO)
    print(f"\n[+] Original:   '{original}'")
    print(f"[+] Recuperado: '{recuperado}'")