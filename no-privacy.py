import os
import json
import base64
import sqlite3
import shutil
import win32crypt
import requests
import hashlib
import time
import re
import sys
import io
from datetime import datetime, timedelta
from Crypto.Cipher import AES


# Configuración de VirusTotal
VT_API_KEY = 'INSERT YOUR VT API KEY HERE'
VT_ANALYZE_URL = "https://www.virustotal.com/api/v3/urls"
VT_URL_INFO_URL = "https://www.virustotal.com/api/v3/urls/{url_id}"

# Colorinches
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

print("""
      
░▒▓███████▓▒░ ░▒▓██████▓▒░       ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒▒▓█▓▒░░▒▓████████▓▒░▒▓█▓▒░       ░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░ ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░ ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░                  
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░       ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓██▓▒░  ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░   ░▒▓█▓▒░                                                                                                                                           
- AlejandroCanoMon                                                                                                                     
      """)
time.sleep(1)


# === Funciones para contraseñas ===

# Función para obtener la clave maestra de cifrado
def get_master_key(browser):
    if browser == "chrome":
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
    elif browser == "edge":
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data", "Local State")
    else:
        raise Exception("Navegador no soportado")

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state_data = json.loads(f.read())
    
    encryption_key = base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])
    encryption_key = encryption_key[5:]
    return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]

# Función para desencriptar contraseñas
def password_decryption(password, encryption_key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return "No Passwords"
# Función para verificar si una credencial es un email válido
def is_valid_email(email):
    
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(email_regex, email) is not None

def hash_email(email):
   
    sha256_hash = hashlib.sha256(email.encode()).hexdigest()
    return sha256_hash[:24]

# Función para verificar si una credencial ha sido filtrada en LeakCheck

def check_leak(credential):
    try:
        # URL base de la API de LeakCheck
        api_url = "https://leakcheck.net/api/public"

        # Si la credencial es un email, la hasheamos y truncamos
        if is_valid_email(credential):
            hashed_email = hashlib.sha256(credential.encode()).hexdigest()[:24]
            payload = {"check": hashed_email}
        else:
            payload = {"check": credential}

        # Realizamos la petición a la API
        response = requests.get(api_url, params=payload)

        # Verificamos el estado de la respuesta
        if response.status_code == 200:
            data = response.json()
            if data['success']:
                if data['found'] > 0:
                    # Si la credencial ha sido filtrada, la mostramos en rojo
                    result = f"{RED}LEAKED\nFound in {data['found']} breaches\nFields: {', '.join(data['fields'])}\nSources:"
                    for source in data['sources']:
                        result += f"\n {RED} - {source['name']} (Date: {source['date']}){RESET}"
                    return result
                else:
                    return f"{GREEN}NOT LEAKED{RESET}"
            else:
                return f"{RED}Error: {data.get('error', 'Unknown error in API response')}{RESET}"
        else:
            return f"{RED}Error: HTTP {response.status_code} - {response.text}{RESET}"
    except Exception as e:
        return f"{RED}Error: {e}{RESET}"

# Función para procesar la base de datos de contraseñas y verificar filtraciones
def process_passwords(browser, credenciales):
    key = get_master_key(browser)
    
    if browser == "chrome":
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data")
    elif browser == "edge":
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data")

    # Hacer una copia de la base de datos para evitar bloqueo
    temp_db = f"{browser}_LoginData_Copy.db"
    shutil.copyfile(db_path, temp_db)

    db = sqlite3.connect(temp_db)
    cursor = db.cursor()

    cursor.execute("SELECT origin_url, action_url, username_value, password_value FROM logins")

    for row in cursor.fetchall():
        main_url, login_page_url, user_name, encrypted_password = row
        decrypted_password = password_decryption(encrypted_password, key)
        
        if user_name or decrypted_password:
            print(f"Browser: {browser}\nURL: {main_url}\nLogin URL: {login_page_url}")

            # Validar si el usuario es un email válido antes de consultar su estado
            if user_name:
                print(f"{CYAN}Usuario: {user_name}{RESET}")
                email_leak_status = check_leak(user_name)
                print(f"Email leak status: {email_leak_status}")
                credenciales.append(f"Usuario: {user_name}")

            # Comprobamos si la contraseña ha sido filtrada
            if decrypted_password and decrypted_password != "No Passwords":
                print(f"{CYAN}Contraseña: {decrypted_password}{RESET}")
                password_leak_status = check_leak(decrypted_password)
                print(f"Password leak status: {password_leak_status}")
                credenciales.append(f"Contraseña: {decrypted_password}")

    cursor.close()
    db.close()
    os.remove(temp_db)

def procesarNavegadores(credenciales):
    chrome_installed = os.path.exists(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State"))
    edge_installed = os.path.exists(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data", "Local State"))

    if chrome_installed:
        print("Chrome detectado. Extrayendo contraseñas...")
        process_passwords("chrome", credenciales)
    else:
        print("Chrome no está instalado.")

    if edge_installed:
        print("Edge detectado. Extrayendo contraseñas...")
        process_passwords("edge", credenciales)
    else:
        print("Edge no está instalado.")

# === Funciones para historial ===

def obtener_historial_navegador(ruta_historial, dias, navegador):
    if not os.path.exists(ruta_historial):
        print(f"No se encontró el archivo de historial de {navegador}.")
        return []
    conn = sqlite3.connect(ruta_historial)
    cursor = conn.cursor()
    fecha_limite = datetime.now() - timedelta(days=dias)
    fecha_unix = int(fecha_limite.timestamp() * 1000000)
    cursor.execute(
        "SELECT url FROM urls WHERE last_visit_time >= ? AND hidden = 0",
        (fecha_unix,)
    )
    historial = cursor.fetchall()
    conn.close()
    return [url[0] for url in historial]

def analizar_url(url):
    headers = {"x-apikey": VT_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(f"{VT_URL_INFO_URL.format(url_id=url_id)}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    elif response.status_code == 404:
        requests.post(VT_ANALYZE_URL, headers=headers, data={"url": url})
        time.sleep(15)
        return analizar_url(url)
    return None

def procesar_historial(dias):
    maliciosas = []
    sospechosas = []
    rutas = {
        "chrome": os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default\History",
        "edge": os.path.expanduser('~') + r"\AppData\Local\Microsoft\Edge\User Data\Default\History"
    }
    for navegador, ruta in rutas.items():
        historial = obtener_historial_navegador(ruta, dias, navegador)
        total_urls = len(historial)
        if total_urls == 0:
            print(f"{RED}No se encontraron URLs en el historial de {navegador}.{RESET}")
            continue
        print(f"Analizando {total_urls} URLs del historial de {navegador}...")
        for i, url in enumerate(historial, start=1):
            resultado = analizar_url(url)
            if resultado:
                print(f"URL: {url}")
                print(f"Maliciosas: {resultado.get('malicious', 0)}")
                print(f"Sospechosas: {resultado.get('suspicious', 0)}")
                if resultado.get("malicious", 0) > 0:
                    maliciosas.append(url)  # Añadir maliciosas
                if resultado.get("suspicious", 0) > 0:  # Cambiado de "elif" a "if"
                    sospechosas.append(url)  # Añadir sospechosas
            # Mostrar progreso
            porcentaje = (i / total_urls) * 100
            print(f"\rProgreso: {porcentaje:.2f}% de URLs analizadas\n", end="")
        
        # Colores para el resultado del análisis de URLs
        if maliciosas:
            print(f"{RED}\nPáginas maliciosas encontradas:{RESET}")
            for url in maliciosas:
                print(f"{RED}{url}{RESET}")
        if sospechosas:  # Ahora también mostramos las sospechosas
            print(f"{YELLOW}\nPáginas sospechosas encontradas:{RESET}")
            for url in sospechosas:
                print(f"{YELLOW}{url}{RESET}")
        if not maliciosas and not sospechosas:
            print(f"{GREEN}\nNo se encontraron páginas maliciosas ni sospechosas.{RESET}")
        
    if not maliciosas and not sospechosas:
        print(f"{GREEN}No se encontraron URLs maliciosas ni sospechosas.{RESET}")
    print("\n")  # Salto de línea después de completar el análisis de un navegador

    # Retorna ambas listas si necesitas procesarlas en otro lugar
    return maliciosas, sospechosas


# === Guardar salida ===

# Función para capturar la salida y luego guardarla en un archivo
def capturar_salida(func):
    # Guardamos la salida estándar actual
    old_stdout = sys.stdout
    # Usamos StringIO para capturar la salida
    new_stdout = io.StringIO()
    sys.stdout = new_stdout
    try:
        # Llamamos a la función original que genera la salida
        func()
    finally:
        # Restauramos la salida estándar original
        sys.stdout = old_stdout
    return new_stdout.getvalue()

# Función para eliminar los códigos de color
def eliminar_colores(texto):
    return re.sub(r"\033\[[0-9;]*m", "", texto)  # Elimina todos los códigos ANSI de color

# Función para guardar la salida en un archivo sin colores
def guardar_en_archivo(salida):
    try:
        salida_sin_colores = eliminar_colores(salida)  # Eliminamos los colores
        with open("analisis.txt", "a", encoding="utf-8") as f:
            f.write(salida_sin_colores + "\n")  # Guardamos la salida sin colores
        print(f"{GREEN}La información ha sido guardada en 'analisis.txt'.{RESET}")
    except Exception as e:
        print(f"{RED}Error al guardar el archivo: {e}{RESET}")


# === Menú principal ===


def main():
    print("Selecciona una opción:")
    print("1. Analizar historial")
    print("2. Extraer contraseñas")
    print("3. Escaneo completo")
    opcion = input("Introduce tu elección (1/2/3): ").strip()

    credenciales = []  # Lista para agrupar usuarios y contraseñas

    if opcion == "1":
        dias = int(input("Introduce el número de días a analizar: "))
        salida = capturar_salida(lambda: procesar_historial(dias))
    elif opcion == "2":
        salida = capturar_salida(lambda: procesarNavegadores(credenciales))
    elif opcion == "3":
        dias = int(input("Introduce el número de días a analizar: "))
        salida = capturar_salida(lambda: [procesar_historial(dias), procesarNavegadores(credenciales)])
    else:
        print("Opción inválida.")
        return

    print(salida)  

    # Preguntar al usuario si quiere guardar la información
    guardar = input(f"{CYAN}¿Deseas guardar esta información en un fichero? (s/n): {RESET}").strip().lower()
    if guardar == "s":
        salida += "\n\n=== Credenciales Extraídas ===\n" + "\n".join(credenciales)
        guardar_en_archivo(salida)

if __name__ == "__main__":
    main()
