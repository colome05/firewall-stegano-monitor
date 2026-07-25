# 🛡️ Orquestador de Seguridad y Detección de Esteganografía en Redes

Este repositorio contiene la implementación de un sistema avanzado de seguridad en redes que simula un entorno continuo de "Blue Team vs Red Team"[cite: 5]. El proyecto coordina la generación de tráfico (legítimo y malicioso), analiza las capturas en busca de canales encubiertos mediante inteligencia artificial y entropía, y exporta alertas estructuradas para su monitorización en tiempo real.

---

## 🏗️ 1. El Orquestador: El Motor de Simulación (El "Ejecutor Tonto")

Es fundamental entender que **el orquestador (`orquestador.py`) es un componente completamente "tonto"**; no realiza ningún cálculo analítico, no lee paquetes y no inspecciona la red. Su única responsabilidad es coordinar la ejecución de los scripts de forma cíclica e ininterrumpida[cite: 5].

El ciclo de vida que sigue el orquestador es estrictamente el siguiente[cite: 5]:
1.  **Tirada de Probabilidad:** Genera un número aleatorio del 1 al 15[cite: 5].
2.  **Selección de Tráfico:** 
    *   Si el número es entre 1 y 11 (probabilidad de 11/15), selecciona el script de tráfico benigno[cite: 5].
    *   Si el número es 12, 13, 14 o 15 (probabilidad de 1/15 cada uno), selecciona uno de los cuatro scripts de malware (Ataques)[cite: 5].
3.  **Ejecución Ciega:** Utiliza `subprocess.run` para ejecutar el generador de tráfico elegido sin saber qué hace internamente[cite: 5].
4.  **Espera de Volcado:** Pausa su ejecución durante 5 segundos para permitir que el generador termine de escribir el archivo `.pcap` en el disco[cite: 5].
5.  **Lanzamiento del IDS:** Ejecuta el script del cortafuegos (`detector_stegano_quic_mejorado3.py`), delegándole todo el trabajo analítico[cite: 5].
6.  **Enfriamiento:** Realiza una cuenta atrás de 30 segundos para estabilizar la red antes de iniciar el siguiente ciclo[cite: 5].

---

## 🟢 2. Generador de Tráfico Benigno

El script `generador_benigno.py` actúa como la base de la simulación. 
*   **Objetivo:** Su función es inyectar tráfico regular en la red para establecer un *baseline* (comportamiento normal).
*   **Importancia:** Al ejecutarse con alta frecuencia (11 de cada 15 veces[cite: 5]), proporciona al cortafuegos los datos necesarios para evitar falsos positivos y entender cómo se ve una red sana antes de que ocurra una exfiltración.

---

## 🔴 3. Los 4 Vectores de Ataque (Scripts Malignos)

Los scripts ofensivos buscan evadir los sistemas de detección inyectando el mensaje "PolHackedYou:)" cifrado con Vernam y una clave precompartida[cite: 1, 2, 3, 4]. Todos los scripts inyectan el tráfico malicioso camuflado entre 500 paquetes de ruido ("chaff") por cada paquete portador de información[cite: 1, 2, 3, 4].

### Tabla Comparativa de Ataques

| Característica | Capa 3 (`inyector_capa3_ip.py`) | Capa 4 Retardos (`inyector_capa4_ipat.py`) | Capa 4 Puertos (`inyector_capa4_puertos.py`) | Capa 7 (`inyector_capa7_payload.py`) |
| :--- | :--- | :--- | :--- | :--- |
| **Mecanismo** | Altera los campos de la cabecera IP[cite: 1]. | Altera el tiempo de llegada entre paquetes (IPAT)[cite: 2]. | Altera el puerto de origen UDP[cite: 3]. | Altera la longitud del paquete UDP[cite: 4]. |
| **Ocultación del Byte** | 1 bit a `Flags`, 3 bits a `TOS`, 2 bits a `TTL`, 2 bits a `IP ID`[cite: 1]. | El retardo es `0.050 + (byte * 0.001)` segundos[cite: 2]. | Se integra en el puerto usando `(prefix << 8) | byte`[cite: 3]. | El tamaño del payload es `1000 + byte`[cite: 4]. |
| **Decodificación** | Ensamblaje binario de los múltiples campos IP leídos[cite: 1]. | Resta del tiempo absoluto entre paquetes secuenciales[cite: 2]. | Aplicación de máscara AND (`0xFF`) sobre el puerto[cite: 3]. | Cálculo de la longitud de la capa `Raw` menos 1000[cite: 4]. |

---

## 🧠 4. El Cortafuegos / IDS (`detector_stegano_quic_mejorado3.py`)

A diferencia del orquestador, el firewall es el verdadero núcleo inteligente del proyecto. Extrae las cabeceras (IP de origen, flags, TOS, ID, TTL, puertos origen, tamaño del payload y tiempos absolutos) del archivo `captura_quic.pcap` y procesa los datos en dos hilos concurrentes[cite: 6]:

### Hilo 1: Motor Espacial (Entropía Multidimensional)
Analiza matemáticamente las cabeceras buscando patrones esteganográficos[cite: 6]:
*   Calcula la **Entropía de Shannon** para identificar la aleatoriedad en los identificadores IP, el TOS, los puertos y los tiempos (IPAT)[cite: 6].
*   Normaliza la entropía dividiéndola entre la entropía máxima posible para evitar sesgos por el volumen de paquetes[cite: 6].
*   **Detección:** Si se supera el umbral de entropía en campos como los puertos origen (indicando *Port Hopping*) o la varianza del tamaño de payload supera 50, confirma el canal encubierto y emite alertas de severidad `CRITICO` asociadas a la IP atacante[cite: 6].

### Hilo 2: Motor IA Temporal Global (LSTM)
Evalúa la red en su conjunto (sin fijarse en IPs específicas) analizando el flujo de tiempos a través de una Inteligencia Artificial:
*   Carga en memoria un modelo pre-entrenado de Red Neuronal LSTM (`modelo_lstm.keras`), un escalador (`scaler_ia.pkl`) y un umbral de error[cite: 6, 7].
*   Extrae características avanzadas de ventanas temporales de 30 paquetes: media, varianza, entropía del histograma, asimetría (skew) y curtosis[cite: 6, 7].
*   Si el error de reconstrucción (MSE) supera el umbral precalculado, infiere que hay un patrón rítmico artificial en los retardos (exfiltración por latencia o DDoS) y emite una advertencia global (`ADVERTENCIA`) sin identificar una IP específica (`0.0.0.0`)[cite: 6].
*   Genera visualmente el gráfico `reporte_lstm_ultimo.png` con la curva temporal y el umbral de alarma[cite: 6].

---

## 📝 5. Generador de Logs Estructurados (JSON)

Cuando el Cortafuegos detecta una intrusión (ya sea por entropía o por LSTM), invoca la función `enviar_alerta_wazuh` para estructurar la salida[cite: 6].
*   **Ruta de destino:** Los eventos se agregan en formato JSON al archivo local `C:\logs_firewall\alertas.json`[cite: 6].
*   **Esquema de datos:** Cada línea del archivo es un objeto independiente que contiene[cite: 6]:
    *   `timestamp`: Marca temporal en formato ISO 8601 UTC[cite: 6].
    *   `app`: Identificador del sistema (`Motor_Esteganografia`)[cite: 6].
    *   `severidad`: Clasificación del impacto (`ADVERTENCIA` o `CRITICO`)[cite: 6].
    *   `src_ip`: La IP identificada, o `0.0.0.0` para alarmas globales temporales[cite: 6].
    *   `descripcion`: Motivo técnico del disparo del IDS (ej. *Inyección Capa 7 detectada...*)[cite: 6].

---

## 📊 6. Pila de Observabilidad (Loki / Grafana)

El archivo `alertas.json` sirve como puente de comunicación hacia la pila de monitorización:
*   **Grafana Alloy:** Un agente en segundo plano monitoriza constantemente el archivo de texto. Al detectar nuevas líneas, extrae las etiquetas (como la severidad) y reenvía el flujo de logs hacia la base de datos de telemetría.
*   **Grafana Loki:** Almacena e indexa estos logs estructurados de forma altamente eficiente.
*   **Paneles de Grafana:** Consumen los datos de Loki para generar gráficos de tarta (basados en las llaves `severidad` del JSON) y tablas de auditoría en tiempo real donde los analistas pueden revisar de un vistazo las IPs bloqueadas (`src_ip`) y las anomalías de entropía (`descripcion`).
