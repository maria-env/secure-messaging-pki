import json
import os

# Funciones JSON
def load_json(path):
    """Función que carga un archivo json"""
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path, obj):
    """Función que guarda un archivo json"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def initialize_files(users_file=r"jsons\users.json", messages_file=r"jsons\messages.json", keys_file=r"jsons\keys.json"):
    """Función que inicializa los archivos json si no existen"""

    # Crea carpeta json si no existe
    if not os.path.exists("jsons"):
        os.mkdir("jsons")

    # Crea archivo de usuarios si no existe
    if not os.path.exists(users_file):
        save_json(users_file, {})
        print(f"Archivo '{users_file}' creado")

    # Crea archivo de mensajes si no existe
    if not os.path.exists(messages_file):
        save_json(messages_file, {"mensajes": []})
        print(f"Archivo '{messages_file}' creado")

    # Crea archivo de claves si no existe
    if not os.path.exists(keys_file):
        save_json(keys_file, {})
        print(f"Archivo '{keys_file}' creado")

    # Crea carpeta de los certificados si no existe
    if not os.path.exists("jsons\\certificados"):
        os.mkdir("jsons\\certificados")
        print(f"Directorio 'jsons\\certificados' creado")