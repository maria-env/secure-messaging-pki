from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import hmac

from funciones_json import load_json, save_json, initialize_files
from crear_usuarios import save_clave_privada, save_clave_publica, cargar_clave_privada

from datetime import datetime

from firmas import firma_mensaje, verificar_firma

from cryptography import x509

from verificador_cadenas import VerificadorCadena

USERS_FILE = r"jsons\users.json"
MESSAGES_FILE = r"jsons\messages.json"
KEYS_FILE = r"jsons\keys.json"

class CifradoHibrido:
    """Clase que se encarga del cifrado híbrido de mensajes (asimétrico + simétrico)"""

    def __init__(self, users_file=USERS_FILE, messages_file=MESSAGES_FILE, keys_file=KEYS_FILE):
        """Inicializamos el sistema de cifrado"""
        self.users_file = users_file
        self.messages_file = messages_file
        self.keys_file = keys_file

        # Inicializamos los ficheros por si no existen
        initialize_files()

        self.users_db = load_json(self.users_file)
        self.messages_db = load_json(self.messages_file)
        self.keys_db = load_json(self.keys_file)

    def generar_claves(self, usuario, contraseña=None):
        """Función que genera la clave pública y privada de un usuario"""
        # Cargamos el json de claves
        self.keys_db = load_json(self.keys_file)

        # Creamos la clave privada
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # valor estándar
            key_size=2048           # longitud típica
        )
        
        # Creamos la clave pública a partir de la privada
        public_key = private_key.public_key()

        # Guardamos las claves en formato PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(contraseña.encode())
        ).decode()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Guardamos las claves en archivos .pem
        save_clave_privada(usuario, private_pem)
        save_clave_publica(usuario, public_pem)

        # Guardamos la clave pública en keys.json
        self.keys_db[usuario] = {
            'clave_publica': public_pem,
            'fecha_creacion': datetime.now().isoformat()
        }
        save_json(self.keys_file, self.keys_db)
        print(f"Clave pública de '{usuario}' guardada en keys.json")


    def cargar_clave_publica_desde_json(self, usuario):
        """Carga la clave pública de un usuario desde keys.json"""
        self.keys_db = load_json(self.keys_file)
        
        if usuario not in self.keys_db:
            raise ValueError(f"No se encontró la clave pública de '{usuario}' en keys.json")
        
        public_pem = self.keys_db[usuario]['clave_publica']
        public_key = serialization.load_pem_public_key(public_pem.encode())
        
        return public_key


    def encriptado_hibrido(self, emisor, receptor, texto, contraseña=None):
        """Función que encripta un mensaje usando cifrado híbrido"""
        # Cargamos los mensajes
        self.messages_db = load_json(self.messages_file)

        # Generamos clave simétrica temporal para este mensaje
        clave_simetrica = Fernet.generate_key()
        fernet = Fernet(clave_simetrica)

        # Ciframos el mensaje con la clave simétrica
        texto_cifrado = fernet.encrypt(texto.encode())

        # Generamos una clave separada para el MAC
        clave_mac = Fernet.generate_key()  # 32 bytes aleatorios

        # Calculamos el HMAC-SHA256 sobre el texto cifrado
        h = hmac.HMAC(clave_mac, hashes.SHA256())
        h.update(texto_cifrado)
        mac = h.finalize()

        # Ciframos la clave simétrica con la clave pública del receptor (desde keys.json)
        public_key = self.cargar_clave_publica_desde_json(receptor)
        clave_simetrica_cifrada = public_key.encrypt(
            clave_simetrica,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        clave_mac_cifrada = public_key.encrypt(
        clave_mac,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

# Lo nuevo

        clave_privada_emisor = cargar_clave_privada(emisor, contraseña)
        firma = firma_mensaje(clave_privada_emisor, texto_cifrado)

        cert_path = f"jsons\\{emisor}\\{emisor}_cert.pem"
        with open(cert_path, "r", encoding="utf-8") as f:
            certificado_emisor = f.read()


        # Guardamos el mensaje con ambos componentes
        mensaje = {
            "emisor": emisor,
            "receptor": receptor,
            "fecha_envio": datetime.now().isoformat(),
            "clave_cifrada": clave_simetrica_cifrada.hex(),
            "texto_cifrado": texto_cifrado.decode(),

            "clave_mac_cifrada": clave_mac_cifrada.hex(),
            "mac": mac.hex(),
            "firma":firma.hex(),
            "certificado_emisor": certificado_emisor
        }

        self.messages_db["mensajes"].append(mensaje)
        save_json(self.messages_file, self.messages_db)

        print(f"Mensaje cifrado y firmado (híbrido) de {emisor} para {receptor}\n")
        return True
    

    def desencriptado_hibrido(self, usuario, contraseña=None):
        """Desencripta los mensajes usando cifrado híbrido"""
        self.messages_db = load_json(self.messages_file)

        # Buscamos los mensajes que le enviaron al usuario
        inbox = [m for m in self.messages_db["mensajes"] if m["receptor"] == usuario]

        if not inbox:
            print(f"No hay mensajes para {usuario}.\n")
            return False

        # Cargamos la clave privada del usuario
        private_key = cargar_clave_privada(usuario, contraseña)

        print(f"--- Bandeja de entrada de {usuario} ---\n")
        for mensaje in inbox:
            try:

                #Comprobamos el certificado
                if "certificado_emisor" not in mensaje:
                    print(f"ERROR: Mensaje sin certificado")
                    continue
        
                # Verificar certificado
                verificador = VerificadorCadena() #Verificamos toda la cadena
                
                valido, msg = verificador.verificar_certificado_desde_pem(
                    certificado_pem=mensaje["certificado_emisor"],
                    nombre_esperado=mensaje["emisor"]
                )

                if not valido:
                    print(f"ERROR: {msg}")
                    continue

                # Extraer clave pública del certificado
                cert_emisor = x509.load_pem_x509_certificate(
                    mensaje["certificado_emisor"].encode()
                )
                clave_publica_emisor = cert_emisor.public_key() 

                #Comprobamos si la firma es correcta
                texto_cifrado = mensaje["texto_cifrado"].encode()

                if "firma" in mensaje:
                    firma = bytes.fromhex(mensaje["firma"])
                    
                    if verificar_firma(clave_publica_emisor, texto_cifrado, firma):
                        print(f" Firma digital verificada correctamente")
                    else:
                        print(f" Firma digital NO válida")

                # Desciframos la clave simétrica con la clave privada
                clave_cifrada_bytes = bytes.fromhex(mensaje["clave_cifrada"])
                clave_simetrica = private_key.decrypt(
                    clave_cifrada_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                clave_mac = private_key.decrypt(
                bytes.fromhex(mensaje["clave_mac_cifrada"]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
                )  

                #Comprobamos si el mac es valido
                mac_recibido = bytes.fromhex(mensaje["mac"])

                h = hmac.HMAC(clave_mac, hashes.SHA256())
                h.update(texto_cifrado)
                h.verify(mac_recibido)

                # Desciframos el mensaje con la clave simétrica
                fernet = Fernet(clave_simetrica)
                texto_plano = fernet.decrypt(texto_cifrado).decode()

                print(f"De: {mensaje['emisor']} | Fecha: {mensaje['fecha_envio']}\n")
                print(f"   Mensaje: {texto_plano}\n")

            except Exception as e:
                print(f"No se pudo descifrar un mensaje: {e}")

        return True