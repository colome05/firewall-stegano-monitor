# 🛡️ Orquestador de Seguridad y Detección de Esteganografía en Redes

Este repositorio contiene la implementación de un sistema avanzado de orquestación de seguridad de red. El proyecto simula un entorno de red completo donde coexiste tráfico legítimo con técnicas sofisticadas de evasión y exfiltración (canales encubiertos y esteganografía de red). 

El sistema utiliza un firewall de inspección profunda, un orquestador analítico basado en ventanas temporales (LSTM) y una pila de observabilidad moderna (Grafana Alloy, Loki y Grafana) para la monitorización en tiempo real.

---

## 🏗️ Arquitectura del Sistema

El flujo de ejecución del proyecto se divide en tres fases principales:
1. **Generación de Tráfico:** Inyección concurrente de paquetes benignos y maliciosos en la interfaz de red simulada.
2. **Inspección y Orquestación:** El Firewall filtra a nivel de paquete, mientras que el Orquestador analiza el comportamiento de los flujos (metadatos, latencias, entropía).
3. **Telemetría y Alertas:** Generación de logs estructurados en JSON, ingesta mediante Alloy/Loki y visualización analítica en Grafana.

---

## 🔬 Análisis Detallado de Componentes

### 1. Generador de Tráfico Benigno
Para que la detección de anomalías sea efectiva, el sistema necesita una línea base (*baseline*) realista. Este script genera flujos de tráfico que imitan el comportamiento normal de usuarios y servicios:
* **Comportamiento:** Establece conexiones TCP/UDP estándar con tamaños de *payload* (carga útil) y distribuciones de latencia que siguen patrones estadísticos normales (ej. distribución de Poisson para la llegada de paquetes).
* **Objetivo:** Entrenar los umbrales dinámicos del orquestador y generar ruido de fondo para poner a prueba la sensibilidad de los algoritmos de detección de canales encubiertos, minimizando los falsos positivos.

### 2. Los 4 Scripts Malignos (Vectores de Ataque)
El núcleo ofensivo del proyecto se compone de cuatro scripts diseñados para evadir defensas tradicionales mediante manipulación a nivel de protocolo y tiempo:

* **Ataque 1: Esteganografía por Temporización (Timing Steganography)**
  * *Mecanismo:* Transmite información oculta alterando deliberadamente el **Inter-Packet Delay (IPD)** (el tiempo entre la llegada de paquetes consecutivos). Por ejemplo, forzar un retraso de 10ms puede representar un bit `0`, y un retraso de 50ms un bit `1`.
  * *Peligro:* La carga útil del paquete es totalmente benigna o está cifrada, por lo que los firewalls tradicionales basados en firmas (IDS/IPS) no detectan nada anómalo.

* **Ataque 2: Esteganografía por Almacenamiento (Storage Steganography)**
  * *Mecanismo:* Oculta la carga útil directamente en los campos de las cabeceras de red (L3/L4) que rara vez son inspeccionados o cuyo valor es predecible/aleatorio. Ejemplos incluyen inyectar bits en el campo *Identification (IP ID)* de IPv4, en los números de secuencia TCP iniciales (ISN), o en opciones TCP no utilizadas.
  * *Peligro:* Permite el paso de comandos de *Command & Control (C2)* a través de firewalls estrictos que solo validan que la estructura del paquete sea correcta según el RFC.

* **Ataque 3: Inyección de Anomalías de Red (Volumétrico / Firmas)**
  * *Mecanismo:* Un ataque más ruidoso que busca explotar el estado de las conexiones. Incluye técnicas como *SYN Flooding*, escaneos de puertos furtivos (Stealth Scans) o el envío de paquetes malformados (ej. flags TCP incompatibles como SYN+FIN) para estudiar la respuesta del cortafuegos.
  * *Peligro:* Diseñado para agotar recursos o desviar la atención del orquestador mientras ocurren exfiltraciones esteganográficas en paralelo.

* **Ataque 4: Exfiltración de Datos por Patrones de Latencia**
  * *Mecanismo:* A diferencia del Ataque 1, este script no codifica bits en retardos individuales, sino que altera la media de latencia a lo largo de **ventanas de tiempo extendidas**. Modula la latencia de forma tan gradual que evade los umbrales estáticos del firewall.
  * *Peligro:* Requiere análisis de series temporales complejas (como modelos LSTM) para identificar que la degradación de la red no es congestión, sino una exfiltración planificada.

### 3. El Firewall (Cortafuegos)
No es un simple filtro estático (`iptables`), sino un motor programado para realizar **Inspección de Estado (Stateful Inspection)** y análisis de cabeceras:
* **Reglas de Capa 3 y 4:** Bloquea inmediatamente el tráfico del Ataque 3 (paquetes malformados, escaneos masivos).
* **Extracción de Metadatos:** Al enfrentarse a los ataques esteganográficos (que son indistinguibles a nivel de firma), el firewall extrae metadatos cruciales de cada conexión (IPs, puertos, varianza de tiempos de llegada, entropía de las cabeceras) y los encapsula para enviarlos al Orquestador.

### 4. El Orquestador
Es el "cerebro" analítico del sistema. Trabaja de forma asíncrona recibiendo los flujos de metadatos del firewall:
* **Análisis de Ventanas (LSTM):** Mantiene ventanas de memoria a corto/largo plazo para analizar el histórico de los flujos. Si la varianza del IPD (Inter-Packet Delay) cambia siguiendo un patrón rítmico, el orquestador identifica la *Esteganografía por temporización*.
* **Evaluación Concurrente:** Diseñado para procesar múltiples flujos de tráfico simultáneamente sin bloqueos, garantizando la detección en tiempo real.
* **Toma de Decisiones:** Si el nivel de anomalía supera los umbrales dinámicos, el orquestador clasifica el evento (Severidad: `ADVERTENCIA`, `CRITICO`) y dispara el módulo de logging.

### 5. Generador de Logs (Formato JSON)
El motor de *logging* centraliza la salida del orquestador escribiendo cada evento de seguridad en un archivo local (`C:\logs_firewall\alertas.json`). Utiliza una estructura JSON estricta para garantizar la compatibilidad con herramientas modernas de ingesta.
* **Estructura del log:**
  ```json
  {
    "timestamp": "2026-07-25 15:30:12",
    "app": "Motor_Esteganografia",
    "severidad": "CRITICO",
    "src_ip": "192.168.1.105",
    "descripcion": "Anomalía temporal: Varianza de IPD supera el umbral LSTM en la ventana actual."
  }
