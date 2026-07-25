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

def obtener_sub_bits(byte_val, inicio, longitud):
    return (byte_val >> inicio) & ((1 << longitud) - 1)

def generar_pcap():
    print("="*60)
    print(" GENERADOR PCAP: CANAL ENCUBIERTO (CAPA 3 - IP LIMPIO)")
    print("="*60)
    mensaje_plano = "PolHackedYou:)"
    mensaje_cifrado = vernam_cifrar(mensaje_plano.encode(), CLAVE_PRECOMPARTIDA)

    archivo = "captura_quic.pcap"
    if os.path.exists(archivo):
      os.remove(archivo)

    ip_normal = "192.168.1.50"
    n_reales = len(mensaje_cifrado)
    bases = generador_bases_ip(SEMILLA_SALTO, n_reales)

    # Inyección isócrona: Un paquete real exactamente cada 500 posiciones
    distancia_fija = 500
    pos_reales = [1000 + (i * distancia_fija) for i in range(n_reales)]
    
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

    for pos in todas:
        if pos in mapa:
            idx, bv, base = mapa[pos]
            be = obtener_sub_bits(bv, 0, 1)
            bt = obtener_sub_bits(bv, 1, 3)
            bttl = obtener_sub_bits(bv, 4, 2)
            bid = obtener_sub_bits(bv, 6, 2)

            pkt = IP(src=IP_ESTEGANO, dst=IP_DESTINO, tos=bt, ttl=64+bttl,
                     id=base+bid, flags="evil" if be else "DF") / \
                  UDP(sport=443, dport=443) / Raw(os.urandom(1200))
        else:
            # Tráfico de ruido completamente estático
            pkt = IP(src=ip_normal, dst=IP_DESTINO, tos=0, ttl=64,
                     id=0, flags="DF") / \
                  UDP(sport=443, dport=443) / Raw(os.urandom(1200))

        # Asignación de tiempo absoluto basado en la posición en la red
        # Esto elimina el jitter causado por las colisiones del set()
        tiempo_base = time.time()
        pkt.time = tiempo_base + (pos * 0.010)
        
        pkts.append(pkt)

    wrpcap(archivo, pkts)
    print(f"[+] PCAP generado: {archivo}")
    return archivo, mensaje_plano, bases

def decodificar(archivo, clave, bases, ip_esperada):
    print("\n" + "="*60)
    print(" DECODIFICACIÓN FORENSE (CAPA 3)")
    print("="*60)

    pkts = rdpcap(archivo)
    resultados = {}

    for pkt in pkts:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        if ip.src != ip_esperada or not (64 <= ip.ttl <= 67):
            continue

        be = 1 if "evil" in str(ip.flags) else 0
        bt = ip.tos & 0x07
        bttl = (ip.ttl - 64) & 0x03

        for i, base in enumerate(bases):
            if base <= ip.id <= base + 3:
                bid = ip.id - base
                bv = (be << 0) | (bt << 1) | (bttl << 4) | (bid << 6)
                resultados[i] = bv
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