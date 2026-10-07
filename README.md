# InfoScann

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**InfoScann** es un escáner de puertos de red rápido, modular y concurrente, escrito en Python.

Es un proyecto de aprendizaje centrado en tareas de reconocimiento de red, como el *banner grabbing* y la identificación del sistema operativo, usando ejecución en paralelo y manipulación de paquetes a bajo nivel.

> **Nota sobre el desarrollo:** el código se ha desarrollado con ayuda de IA (Claude). Mi trabajo se ha centrado en el diseño de la herramienta, las pruebas y la validación de los resultados mediante análisis de tráfico con `tcpdump`, lo que me permitió detectar falsos positivos y entender qué huellas deja un escaneo desde el punto de vista del defensor.

## Cómo funciona por dentro

La lógica principal (`port_scanner.py`) se divide en estas fases para cada puerto analizado:

- **Paralelismo:** para que el escaneo sea rápido con muchas IPs y puertos, se usa `concurrent.futures.ThreadPoolExecutor`. En lugar de ir puerto a puerto en un bucle bloqueante, el programa reparte las pruebas entre un conjunto de hilos que se ejecutan en paralelo.

- **Detección de puertos (dos técnicas, se elige con `-s`):**
  - **Connect scan** (por defecto, no necesita privilegios): completa el *handshake* TCP con la librería estándar `socket` (`connect_ex`). La familia del socket (`AF_INET` / `AF_INET6`) se adapta a la versión de IP, así que también funciona con IPv6.
  - **SYN scan** (`-s syn`, necesita root): escaneo *half-open* con `scapy`. Se envía solo un SYN y se clasifica la respuesta: SYN-ACK significa abierto (y se envía un RST para no completar la conexión), RST significa cerrado, y la ausencia de respuesta significa filtrado. Si no hay permisos para sockets raw, avisa y vuelve al connect scan.

- **Estados de los puertos:** cada puerto se marca como **abierto**, **cerrado** (el equipo responde con RST) o **filtrado** (sin respuesta o ICMP unreachable, normalmente porque un firewall descarta el paquete).

- **Banner grabbing activo (connect scan):** el banner se lee por el mismo socket que detectó el puerto abierto, así que cada puerto abierto cuesta una sola conexión TCP. En puertos web (80, 443, 8080, 8443) se envía una petición `HEAD / HTTP/1.1` para forzar una respuesta identificable. En puertos TLS (443, 8443) la conexión se envuelve primero con el módulo `ssl` de Python (con la verificación de certificados desactivada a propósito, porque un escáner debe poder tratar certificados autofirmados o caducados) y se muestran el sujeto, el emisor y la fecha de caducidad del certificado.

- **Identificación pasiva del sistema operativo (SYN scan):** la herramienta lee el TTL (o *Hop Limit* en IPv6) del SYN-ACK recibido y estima el sistema operativo (por ejemplo, TTL 64 suele indicar Linux y TTL 128, Windows). No hace falta enviar ningún paquete extra.

- **Informe:** los resultados se muestran en directo y al final se resumen en una tabla ordenada por IP y puerto, con el nombre del servicio registrado (`socket.getservbyport`). Los grupos grandes de puertos cerrados o filtrados se agrupan en un contador "No mostrados", como hace nmap. Con `-o` se puede exportar todo a JSON.

## Tecnologías y librerías

- **`socket`:** conexiones TCP/IP a bajo nivel.
- **`concurrent.futures`:** gestión de la concurrencia y del número de hilos.
- **`scapy`:** creación y análisis de los paquetes raw del SYN scan.
- **`ssl` + `cryptography`:** *handshake* TLS en puertos HTTPS y lectura del certificado del servidor.
- **`json`:** exportación de resultados en un formato que pueden ingerir los SIEM.
- **`argparse`:** parámetros de línea de comandos con estilo POSIX.
- **`ipaddress`:** interpretación de IPs sueltas y de subredes completas (bloques CIDR).
- **`pyfiglet`:** un toque estético para el banner de inicio.

## Primeros pasos

### Requisitos

- Python 3.8 o superior.
- El connect scan por defecto no necesita privilegios especiales.
- El SYN scan (`-s syn`) y la identificación del sistema operativo necesitan paquetes raw:
  - **Windows:** Npcap instalado y la consola ejecutada como Administrador (lo exige Scapy).
  - **Linux / macOS:** privilegios de superusuario (`sudo`) o la capacidad `CAP_NET_RAW`.

### Instalación

El proyecto está empaquetado con `pyproject.toml`, así que se puede instalar como un comando más del sistema:

```bash
# Desde el directorio del código:
pip install .

# Una vez instalado, se puede ejecutar desde cualquier sitio:
infoscann -t 127.0.0.1 -p 80,443
```

### Con Docker (recomendado)

La imagen se construye y publica automáticamente en GitHub Container Registry, así que se puede usar sin instalar dependencias:

```bash
# --privileged es necesario para el SYN scan y la identificación del SO mediante sockets raw
docker run --privileged ghcr.io/fernando-redondo1/port-scanner:main -t scanme.nmap.org -s syn
```

## Ejemplo de uso

![Ejemplo de uso](screenshot.png)

### Modos y ejemplos

- **Modo sigiloso (por defecto):** `infoscann -t scanme.nmap.org`
- **Modo agresivo:** `infoscann -t scanme.nmap.org -m aggressive`
- **Puertos concretos:** `infoscann -t 127.0.0.1 -p 21,22,80,443,8080`
- **Rangos de puertos (se pueden mezclar con puertos sueltos):** `infoscann -t 127.0.0.1 -p 1-1024` o `infoscann -t 127.0.0.1 -p 22,80,8000-8100`
- **SYN scan con identificación del SO (necesita root):** `sudo infoscann -t 127.0.0.1 -s syn`
- **Objetivo IPv6:** `infoscann -t ::1 -p 22,80,443`
- **Exportar a JSON (por ejemplo, para un SIEM):** `infoscann -t 127.0.0.1 -p 1-1024 -o results.json`

El fichero JSON incluye los metadatos del escaneo (objetivo, tipo de escaneo y hora de inicio y fin en UTC) y un registro por puerto:

```json
{
  "ip": "127.0.0.1",
  "port": 443,
  "state": "open",
  "service": "https",
  "os": "Unknown (needs -s syn)",
  "banner": "HTTP/1.1 302 Found ...",
  "tls": {
    "subject": "CN=example.local",
    "issuer": "CN=Example CA",
    "expires": "2027-01-01T00:00:00+00:00"
  },
  "vulnerability": null
}
```

## Novedades

- **Una conexión por puerto abierto:** el connect scan reutiliza el mismo socket para la detección y el banner grabbing, y ya no envía un paquete extra para identificar el SO.
- **Soporte TLS:** los puertos HTTPS se envuelven con `ssl` y se muestran el sujeto, el emisor y la caducidad del certificado.
- **Soporte IPv6:** la familia del socket sigue la versión de IP y los nombres se resuelven con `getaddrinfo` (incluidos los registros AAAA).
- **Tabla resumen ordenada:** los resultados se ordenan por IP y puerto al final del escaneo.
- **Cerrados frente a filtrados:** ahora se distinguen las respuestas RST de los timeouts, en lugar de ignorarlas.
- **SYN scan (`-s syn`):** escaneo *half-open* con scapy, que aprovecha el TTL del SYN-ACK para identificar el SO, con vuelta automática al connect scan si no hay privilegios.
- **Rangos de puertos:** `1-1024` y listas mixtas como `22,80,8000-8100`.
- **Nombres de servicio:** desde la base de datos de servicios del sistema mediante `getservbyport` (protegido para hilos, porque la llamada interna en C no lo es).
- **Exportación a JSON (`-o`):** todos los resultados más los metadatos del escaneo.

## Próximos pasos

Hecho desde la primera versión: SYN scan y soporte TLS/SSL.

Áreas de mejora identificadas:

- **Escalabilidad del detector de vulnerabilidades:** la comprobación pasiva lee de una lista fija en memoria. El siguiente paso sería consultar de forma asíncrona bases de datos de CVE o Vulners para comparar con vulnerabilidades reales.
- **Detección de servicios en modo SYN:** el SYN scan nunca completa el *handshake*, así que no obtiene banners. Una sonda opcional sobre los puertos abiertos (como `-sV` en nmap) recuperaría banners, datos TLS y comprobaciones de vulnerabilidades.
- **Redes IPv6 grandes:** los rangos CIDR se expanden en una lista completa de equipos, lo que funciona en subredes IPv4 pero no en un /64 de IPv6. Los rangos grandes deberían rechazarse o procesarse por partes.
- **Salida en streaming:** un modo NDJSON (un evento JSON por línea, escrito al terminar cada puerto) permitiría a los agentes del SIEM leer el fichero durante escaneos largos.
- **Tests automáticos:** pruebas unitarias del análisis de puertos, la clasificación de estados y el formato del informe, ejecutadas en CI antes de publicar la imagen de Docker.

## Licencia

Distribuido bajo la licencia MIT. Consulta el fichero `LICENSE`.
