import os
from cryptography.hazmat.primitives import serialization

def initialize_folder(usuario):
    """Función que inicializa las carpetas de los usuarios"""

    folder = f"jsons\\{usuario}"
    if not os.path.exists(folder):
        os.makedirs(folder)
        print(f"Carpeta '{folder}' creada")


def save_clave_privada(usuario, clave_pem):
    """Función que guarda la clave privada"""

    path = f"jsons\\{usuario}\\claveprivada.pem"
    with open(path, "w", encoding="utf-8") as f:
        f.write(clave_pem)
    print(f"Clave privada guardada en '{path}'")


def save_clave_publica(usuario, clave_pem):
    """Función que guarda la clave pública"""

    path = f"jsons\\{usuario}\\clavepublica.pem"
    with open(path, "w", encoding="utf-8") as f:
        f.write(clave_pem)
    print(f"Clave pública guardada en '{path}'")


def cargar_clave_privada(usuario, contraseña=None):
    """Lee y devuelve la clave privada del usuario desde su archivo .pem"""

    path = f"jsons\\{usuario}\\claveprivada.pem"
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=contraseña.encode())

    return private_key


def cargar_clave_publica(usuario):
    """Lee y devuelve la clave pública del usuario desde su archivo .pem"""

    path = f"jsons\\{usuario}\\clavepublica.pem"
    with open(path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return public_key