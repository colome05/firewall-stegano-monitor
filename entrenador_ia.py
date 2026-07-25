import os
import pickle
import numpy as np
from scapy.all import PcapReader, IP, UDP
from scipy.stats import entropy, skew, kurtosis
from sklearn.preprocessing import MinMaxScaler

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import tensorflow as tf
tf.get_logger().setLevel('ERROR')
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Input, LSTM, Dense, RepeatVector, TimeDistributed

def extraer_tiempos(pcap_file):
    print(f"[*] Leyendo PCAP base: {pcap_file}")
    tiempos_llegada = []
    tiempo_anterior = None
    try:
        with PcapReader(pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                if pkt.haslayer(IP) and pkt.haslayer(UDP):
                    timestamp_abs = float(pkt.time)
                    if tiempo_anterior is not None:
                        delta = (timestamp_abs - tiempo_anterior) * 1000.0
                        tiempos_llegada.append(max(delta, 0.001))
                    tiempo_anterior = timestamp_abs
    except Exception as e:
        print(f"[!] Error: {e}")
    return tiempos_llegada

def entrenar_y_guardar():
    print("="*60)
    print(" BLUE TEAM: ENTRENAMIENTO OFFLINE DE IA (LSTM)")
    print("="*60)
    
    # 1. Extraer tráfico benigno
    ipats = extraer_tiempos("captura_quic.pcap")
    
    window_size = 30
    caracteristicas = []

    print("[*] Calculando características matemáticas...")
    for i in range(len(ipats) - window_size):
        ventana = ipats[i : i + window_size]
        hist, _ = np.histogram(ventana, bins=10, density=True)
        asimetria = skew(ventana)
        curtosis = kurtosis(ventana)

        caracteristicas.append([
            np.mean(ventana), np.var(ventana), entropy(hist + 1e-9),
            np.mean(np.abs(np.diff(ventana))),
            0.0 if np.isnan(asimetria) else asimetria,
            0.0 if np.isnan(curtosis) else curtosis
        ])

    features = np.array(caracteristicas)
    
    # 2. Entrenar el escalador y guardarlo
    scaler = MinMaxScaler()
    features_escaladas = scaler.fit_transform(features)
    
    with open("scaler_ia.pkl", "wb") as f:
        pickle.dump(scaler, f)
    print("[+] Escalador (MinMaxScaler) guardado en 'scaler_ia.pkl'")

    time_steps = 5
    X_train = np.array([features_escaladas[i : i + time_steps] for i in range(len(features_escaladas) - time_steps)])
    num_features = X_train.shape[2]

    # 3. Diseñar y entrenar la red LSTM
    print("[*] Entrenando Red Neuronal LSTM (Esto tomará unos segundos)...")
    modelo = Sequential([
        Input(shape=(time_steps, num_features)),
        LSTM(16, activation='relu', return_sequences=True),
        LSTM(8, activation='relu', return_sequences=False),
        RepeatVector(time_steps),
        LSTM(8, activation='relu', return_sequences=True),
        LSTM(16, activation='relu', return_sequences=True),
        TimeDistributed(Dense(num_features))
    ])

    modelo.compile(optimizer='adam', loss='mse')
    modelo.fit(X_train, X_train, epochs=20, batch_size=32, validation_split=0.1, verbose=0)

    # 4. Guardar modelo y umbral de alarma
    modelo.save("modelo_lstm.keras")
    print("[+] Modelo LSTM guardado en 'modelo_lstm.keras'")
    
    errores_train = np.mean(np.power(X_train - modelo.predict(X_train, verbose=0), 2), axis=(1, 2))
    umbral = np.mean(errores_train) + (4 * np.std(errores_train))
    
    with open("umbral_ia.txt", "w") as f:
        f.write(str(umbral))
    print(f"[+] Umbral de alarma ({umbral:.6f}) guardado en 'umbral_ia.txt'")
    print("="*60)
    print("[+] ENTRENAMIENTO FINALIZADO. EL FIREWALL YA PUEDE USAR LA IA.")

if __name__ == "__main__":
    entrenar_y_guardar()