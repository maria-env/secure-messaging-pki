import os
from cryptography.hazmat.primitives import serialization

def initialize_folder(autoridad):
    """Función que inicializa las carpetas de los usuarios"""

    folder = f"jsons\\certificados\\{autoridad}"
    if not os.path.exists(folder):
        os.makedirs(folder)
        print(f"Carpeta '{folder}' creada")


def save_clave_privada(autoridad, clave_pem):
    """Función que guarda la clave privada"""

    path = f"jsons\\certificados\\{autoridad}\\claveprivada.pem"
    with open(path, "w", encoding="utf-8") as f:
        f.write(clave_pem)
    print(f"Clave privada guardada en '{path}'")


def save_clave_publica(autoridad, clave_pem):
    """Función que guarda la clave pública"""

    path = f"jsons\\certificados\\{autoridad}\\clavepublica.pem"
    with open(path, "w", encoding="utf-8") as f:
        f.write(clave_pem)
    print(f"Clave pública guardada en '{path}'")


def cargar_clave_privada(autoridad):
    """Lee y devuelve la clave privada del autoridad desde su archivo .pem"""

    path = f"jsons\\certificados\\{autoridad}\\claveprivada.pem"
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    return private_key


def cargar_clave_publica(autoridad):
    """Lee y devuelve la clave pública del autoridad desde su archivo .pem"""

    path = f"jsons\\certificados\\{autoridad}\\clavepublica.pem"
    with open(path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return public_key

def save_certificado(autoridad, cert_pem):

    path = f"jsons\\certificados\\{autoridad}_cert.pem"
    with open(path, "w", encoding="utf-8") as f:
        f.write(cert_pem)