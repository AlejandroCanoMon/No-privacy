# 🛡️ **No-Privacy**  

No-Privacy es una herramienta de análisis forense diseñada para extraer contraseñas y analizar historiales de navegadores como Chrome y Edge. También permite verificar si las credenciales y contraseñas han sido comprometidas en brechas de seguridad (usando LeakCheck) y analizar URLs para detectar actividades maliciosas (usando VirusTotal).

---

## 🚀 **Características principales**
- **Extracción de contraseñas**: Recupera contraseñas guardadas en los navegadores Chrome y Edge.
- **Verificación de filtraciones**: Comprueba si las credenciales o contraseñas han sido comprometidas en brechas de seguridad conocidas.
- **Análisis del historial**: Revisa el historial de los navegadores y detecta URLs maliciosas o sospechosas usando la API de VirusTotal.
- **Soporte multi-navegador**: Compatible con navegadores basados en Chromium, como Chrome y Edge.
- **Colores interactivos en consola**:
  - **🟥 Rojo**: Elementos maliciosos o comprometidos.
  - **🟨 Amarillo**: Elementos sospechosos.
  - **🟦 Cian**: Contraseñas extraídas.
  - **🟩 Verde**: Resultados seguros o no comprometidos.
- **Opciones de guardado**: Permite guardar los resultados en un archivo de texto.

---

## 🖥️ **Requisitos del sistema**
- **Sistema operativo**: Windows 10 o superior.
- **Lenguaje**: Python 3.7 o superior.
- **Bibliotecas necesarias**: 
  - `requests`
  - `hashlib`
  - `win32crypt`
  - `pycryptodome`

---

## ⚙️ **Instalación**
1. **Clonar el repositorio**:  
   ```bash
   git clone https://github.com/alejandrocanomon/no-privacy.git
   cd no-privacy
2. **Instalar dependencias**:  
   Ejecuta el siguiente comando para instalar todas las bibliotecas necesarias:  
   ```bash
   pip install requests hashlib win32crypt pycryptodome 
3. **Configurar las claves API**:
   - Obtén una clave de VirusTotal en [VirusTotal API](https://www.virustotal.com/gui/join-us).
   - (Opcional) Configura el acceso a la API pública de LeakCheck.
   - Sustituye las claves en las variables `VT_API_KEY` y otras según sea necesario en el código.

## 🛠️ **Uso**

Ejecuta el script principal desde la terminal:
    ```bash
    python no-privacy.py

---

## 🔒 **Consideraciones de seguridad**
- Este proyecto debe utilizarse exclusivamente para análisis forense autorizado. **No lo utilices para actividades ilegales o sin el consentimiento del propietario del sistema.**
- Las credenciales extraídas deben manejarse con responsabilidad y almacenarse de forma segura.

---

## 📜 **Licencia**
Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

## 🛠️ **Contribuciones**
¡Las contribuciones son bienvenidas! Si encuentras errores o quieres agregar nuevas características, no dudes en abrir un issue o un pull request.


---

## 🌟 **Agradecimientos**
Este proyecto fue creado con el propósito de fortalecer el análisis forense en navegadores y apoyar la ciberseguridad.

