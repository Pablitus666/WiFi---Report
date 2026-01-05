# 📡 WiFi Scanner (Windows)

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows)
![GUI](https://img.shields.io/badge/GUI-Tkinter-success)
![Build](https://img.shields.io/badge/Build-PyInstaller-orange)
![Executable](https://img.shields.io/badge/Mode-Onefile-critical)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

Aplicación gráfica en Python que permite **escanear redes Wi-Fi guardadas en Windows**, mostrar sus contraseñas (cuando están disponibles) y **generar un reporte en archivo `.txt`** con un diseño claro y profesional.

---

![Social Preview](images 2/Preview.png)

---

## ✨ Características

- 🔍 Escaneo de redes Wi-Fi guardadas en el sistema
- 🔐 Obtención de contraseñas (cuando el sistema lo permite)
- ⚡ Escaneo optimizado con múltiples hilos
- 🧠 Cache del último escaneo (no repite procesos innecesarios)
- ⏳ Indicador visual de escaneo (spinner animado)
- 📊 Muestra la cantidad de redes encontradas
- 💾 Exportación a archivo `.txt`
- 🖼️ Interfaz gráfica elegante y consistente
- 🪟 Verificación automática de sistema operativo (solo Windows)
- 👨‍💻 Ventana de información del desarrollador

---

## 🖥️ Requisitos

- **Sistema Operativo:** Windows 10 / 11  
- **Permisos:** Usuario con acceso a perfiles Wi-Fi  
- **Python:** *No requerido* (versión `.exe`)

---

## 📷 Capturas de pantalla

<p align="center">
  <img src="images 2/screenshot.png?v=2" alt="Vista previa de la aplicación" width="600"/>
</p>

---


## 🚀 Instalación y uso

### Opción 1: Ejecutable (.exe) — Recomendado
1. Descarga el archivo `.exe`
2. Ejecuta el programa
3. Presiona **SCAN** para escanear redes
4. Presiona **SAVE** para guardar el reporte
5. Presiona **INFO** para ver información del desarrollador

### Opción 2: Ejecutar desde código fuente
```bash
python wifi_scanner.py
📄 Reporte generado
El archivo .txt incluye:

Banner ASCII

Fecha y hora

Usuario del sistema

Sistema operativo

Lista de redes Wi-Fi y contraseñas

Firma del desarrollador

Ejemplo:

yaml
Copiar código
Redes encontradas: 12
(Este dato se muestra en pantalla, no se guarda en el archivo)

---

🛠️ Tecnologías utilizadas
Python 3

Tkinter

PIL (Pillow)

netsh (Windows)

ThreadPoolExecutor

---

📦 Empaquetado
El ejecutable fue generado con:

PyInstaller

Modo: --onefile

Interfaz: GUI (sin consola)

Tamaño final: 25 MB

---

⚠️ Aviso legal
Este software muestra contraseñas Wi-Fi almacenadas localmente en el sistema.
Úselo únicamente en equipos de su propiedad o con autorización expresa.

---

👨‍💻 Autor
Pablo Téllez A.
📍 Tarija - Bolivia
🗓️ 2024

---

⭐ ¿Te gustó el proyecto?
¡No olvides dejar una estrella ⭐ en el repositorio!

---