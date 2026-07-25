# 🛡️ Sistema Inteligente de Detección y Orquestación para Cortafuegos con Monitorización en Tiempo Real

Repositorio oficial del sistema avanzado de seguridad de redes y orquestación de tráfico. Este proyecto implementa un entorno de pruebas completo capaz de simular tráfico legítimo y múltiples vectores de ataque orientados a canales encubiertos, utilizando un motor de análisis inteligente, un generador estructurado de eventos de seguridad y una pila moderna de observabilidad basada en Grafana y Loki.

---

## 📑 Tabla de Contenidos
1. [Arquitectura General](#-arquitectura-general)
2. [Componentes del Sistema](#-componentes-del-sistema)
   - [1. Generador de Tráfico Benigno](#1-generador-de-tráfico-benigno)
   - [2. Los 4 Vectores de Ataque](#2-los-4-vectores-de-ataque)
   - [3. El Cortafuegos (Firewall Engine)](#3-el-cortafuegos-firewall-engine)
   - [4. El Orquestador](#4-el-orquestador)
   - [5. Generador de Logs Estructurados (JSON)](#5-generador-de-logs-estructurados-json)
   - [6. Almacenamiento y Visualización (Loki / Grafana)](#6-almacenamiento-y-visualización-loki--grafana)
3. [Estructura del Repositorio](#-estructura-del-repositorio)
4. [Instalación y Despliegue](#-instalación-y-despliegue)

---

## 🏗️ Arquitectura General

El flujo de datos del sistema está diseñado como un pipeline cerrado de seguridad: el tráfico (tanto legítimo como malicioso) es evaluado por el cortafuegos. El orquestador procesa y analiza las métricas de comportamiento mediante modelos analíticos y ventanas temporales, generando alertas detalladas que se escriben en formato JSON, son indexadas por el agente de Loki y finalmente se exponen de forma visual en los paneles de Grafana.

---

## 🧩 Componentes del Sistema

### 1. Generador de Tráfico Benigno
* **Función:** Simula la actividad de red normal, regular y esperada de los usuarios legítimos dentro de la infraestructura.
* **Propósito:** Evitar falsos positivos y establecer una línea base de comportamiento (*baseline*) sobre la cual el sistema de seguridad aprende a diferenciar el tráfico legítimo del anómalo.

### 2. Los 4 Vectores de Ataque
El entorno integra simulaciones de cuatro tipos específicos de ataques orientados a comprometer la red o camuflar información:
1. **Ataque de Canales Encubiertos por Temporización (Timing Steganography):** Modificación deliberada de los intervalos de tiempo entre paquetes enviados para transmitir datos ocultos de forma binaria sin alterar el contenido del paquete.
2. **Ataque de Canales Encubiertos por Almacenamiento (Storage Steganography):** Ocultación de cargas útiles de información dentro de campos de cabeceras de red que habitualmente no son inspeccionados de forma exhaustiva por los filtros tradicionales.
3. **Inyección de Tráfico Malicioso / Anomalías de Red:** Inundación o envío de patrones de paquetes con firmas irregulares orientadas a desestabilizar servicios.
4. **Exfiltración de Datos por Patrones de Latencia:** Variación sostenida del retardo en las respuestas para transferir información confidencial eludiendo las inspecciones de contenido superficiales.

### 3. El Cortafuegos (Firewall Engine)
* **Función:** Actúa como la primera línea de defensa perimetral. Intercepta los flujos de datos entrantes y salientes aplicando reglas de filtrado estáticas y dinámicas.
* **Integración:** Trabaja en conjunto con el motor analítico para bloquear o marcar aquellos paquetes que muestran indicios de manipulación o anomalías esteganográficas.

### 4. El Orquestador
* **Función:** Es el cerebro central del sistema. Se encarga de coordinar la ejecución de los componentes, gestionar el flujo de análisis y evaluar las ventanas de tiempo.
* **Análisis de Anomalías:** Incorpora lógica de evaluación (incluyendo umbrales basados en ventanas de latencia y modelos de comportamiento tipo LSTM) para detectar desviaciones estadísticas que escapan a las reglas estáticas del cortafuegos.

### 5. Generador de Logs Estructurados (JSON)
* **Función:** Cada vez que el orquestador detecta una incidencia, anomalía o violación de seguridad, genera un registro estructurado con un esquema estricto.
* **Formato del Log:** Los eventos se almacenan localmente (por ejemplo, en `C:\logs_firewall\alertas.json`) estructurados en formato JSON, conteniendo campos clave como:
  * `timestamp`: Marca temporal de alta precisión.
  * `app`: Identificador del motor emisor (ej. *Motor_Esteganografia*).
  * `severidad`: Nivel de criticidad (`ADVERTENCIA`, `CRITICO`, etc.).
  * `src_ip`: Dirección IP de origen del tráfico evaluado.
  * `descripcion`: Detalle técnico de la anomalía (ej. *Anomalía temporal detectada: 14 ventanas de latencia superaron el umbral LSTM*).

### 6. Almacenamiento y Visualización (Loki / Grafana)
* **Recogida y Transporte (Grafana Alloy):** Un agente ligero monitorea de forma continua el archivo `alertas.json` y retransmite los logs en tiempo real hacia la base de datos de registros.
* **Indexación (Grafana Loki):** Almacena y procesa eficientemente los flujos de texto sin necesidad de indexar todos los campos de forma relacional tradicional, optimizando el rendimiento.
* **Panel de Control (Grafana):** Presenta los datos a través de dos vistas principales:
  * *Gráfico de Tarta (Pie Chart):* Desglose porcentual y cuantitativo de las alertas agrupadas por su nivel de **severidad**.
  * *Tabla de Auditoría:* Extracción limpia y formateada en columnas de los campos JSON para auditar de forma inmediata las IPs de origen, marcas temporales y descripciones de los ataques.

---

## 📂 Estructura del Repositorio

```text
firewall-stegano-monitor/
│
├── README.md               <-- Documentación exhaustiva del proyecto
├── src/
│   ├── orquestador.py      <-- Núcleo de orquestación y evaluación de anomalías
│   ├── firewall.py         <-- Lógica del cortafuegos y reglas de filtrado
│   ├── generadores/        <-- Módulos de tráfico benigno y vectores de ataque
│   └── logger.py           <-- Motor de generación de alertas estructuradas JSON
├── config/
│   └── alloy-config.alloy  <-- Configuración del agente de recogida de logs
└── docs/
    └── images/             <-- Capturas de pantalla del dashboard de Grafana
