from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from funciones_json import initialize_files
import os
from datetime import datetime, timedelta, timezone


class AutoridadCertificacion:
    """Clase para gestionar la Autoridad de Certificación"""
    
    def __init__(self, nombre, es_raiz=False, ca_superior=None):
        """ Inicializa una Autoridad """
        self.nombre = nombre
        self.es_raiz = es_raiz  #Es true si es la autoridad madre
        self.ca_superior = ca_superior #Si no es la autoridad madre, esta es su superior
        self.clave_privada = None
        self.clave_publica = None
        self.certificado = None
        
        self._crear_carpetas()
        
        initialize_files() 


    def _crear_carpetas(self):
        """Crea la estructura de carpetas para esta CA"""
        # Si es raíz: jsons/certificados/CA_Raiz/
        # Si es subordinada: jsons/certificados/CA_Raiz/CA_SubX/
            
        ca_path = self.determinar_raiz()
            
        # Crear todas las carpetas necesarias
        if not os.path.exists(ca_path):
            os.makedirs(ca_path)
            print(f"Carpeta creada: {ca_path}\n")
            
        # Crear carpeta de usuarios solo si es subordinada
        if not self.es_raiz:
            usuarios_path = f"{ca_path}\\usuarios"
            if not os.path.exists(usuarios_path):
                os.makedirs(usuarios_path)
                print(f"Carpeta de usuarios de {self.nombre} creada: {usuarios_path}\n")
    

    def determinar_raiz(self):
        if self.es_raiz:
            # CA Raíz va directamente en certificados/
            ca_path = f"jsons\\certificados\\{self.nombre}"
        else:
            # CA Subordinada va dentro de CA_Raiz/
            if not self.ca_superior:
                raise ValueError("CA subordinada no tiene una CA superior")
            ca_path = f"jsons\\certificados\\{self.ca_superior.nombre}\\{self.nombre}"

        return ca_path
    
    
    def path_usuarios(self):
        """Devuelve la ruta de donde se encuentra el certificado de un usuario"""
        return f"jsons\\certificados\\{self.ca_superior.nombre}\\{self.nombre}\\usuarios"
    

    def guardar_clave_privada(self, clave_pem):
        """Función que guarda la clave privada"""

        ca_path = self.determinar_raiz()
        priv_path = os.path.join(ca_path, "claveprivada.pem")
        
        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(clave_pem)
        print(f"Clave privada guardada en '{priv_path}'\n")


    def guardar_clave_pública(self, clave_pem):
        """Función que guarda la clave pública"""

        ca_path = self.determinar_raiz()
        public_path = os.path.join(ca_path, "clavepublica.pem")
        
        with open(public_path, "w", encoding="utf-8") as f:
            f.write(clave_pem)
        print(f"Clave pública guardada en '{public_path}'\n")
    

    def cargar_clave_privada(self):
        """Lee y devuelve la clave privada del autoridad desde su archivo .pem"""

        ca_path = self.determinar_raiz()
        priv_path = os.path.join(ca_path, "claveprivada.pem")
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        return private_key


    def cargar_clave_publica(self):
        """Lee y devuelve la clave pública del autoridad desde su archivo .pem"""

        ca_path = self.determinar_raiz()
        public_path = os.path.join(ca_path, "clavepublica.pem")
        with open(public_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        return public_key
        
        
    def generar_claves(self):
        """Genera el par de claves RSA para la CA"""
        
        self.clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.clave_publica = self.clave_privada.public_key()


    def guardar_certificado(self):
        """Guarda el certificado de la CA en formato PEM"""
        cert_pem = self.certificado.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()

        # Guardamos el certificado en PEM
        ca_path = self.determinar_raiz()
        path_carpeta = f"{ca_path}\\certificado.pem"

        with open(path_carpeta, "w", encoding="utf-8") as f:
            f.write(cert_pem)

    def guardar_claves(self):
        """Guarda las claves privada y pública de la CA"""

        # Guardar clave privada
        private_pem = self.clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        self.guardar_clave_privada(private_pem)
        
        # Guardar clave pública
        public_pem = self.clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        self.guardar_clave_pública(public_pem)


    def crear_certificado_raiz(self):
        """Crea un certificado autofirmado para la CA raíz"""
        if not self.es_raiz:
            raise ValueError("Solo las CA raíz pueden crear certificados autofirmados\n")
        
        # Generar claves
        self.generar_claves()
        
        # Crear el subject/issuer (para CA raíz son iguales)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.nombre),
        ])

        ahora = datetime.now(timezone.utc)
        
        # Crear certificado autofirmado
        self.certificado = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.clave_publica)
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora)
            .not_valid_after(ahora + timedelta(days=3650))  # 10 años
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(self.clave_privada, hashes.SHA256())
        )
        
        # Guardar certificado y claves
        self.guardar_certificado()
        self.guardar_claves()
        
        print(f"Certificado raíz creado para '{self.nombre}'\n")
        return self.certificado
        

    def crear_certificado_subordinado(self, ca_subordinada):
        """Crea un certificado para una CA subordinada (self es la CA superior)"""
        
        # Generar claves para la subordinada
        ca_subordinada.generar_claves()
        
        # Crear el subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, ca_subordinada.nombre),
        ])
        
        
        # Crear certificado firmado por esta CA (self)
        ahora = datetime.now(timezone.utc)

        ca_subordinada.certificado = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificado.subject)
            .public_key(ca_subordinada.clave_publica)
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora)
            .not_valid_after(ahora + timedelta(days=1825))  # 5 años
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .sign(self.clave_privada, hashes.SHA256())
        )
        
        # Guardar certificado y claves
        ca_subordinada.guardar_certificado()
        ca_subordinada.guardar_claves()
        
        print(f"Certificado subordinado creado para '{ca_subordinada.nombre}' por '{self.nombre}'\n")
        return ca_subordinada.certificado


    def emitir_certificado_usuario(self, usuario, clave_publica_usuario):
        """Emite un certificado para un usuario final"""
        
        # Crear el subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, usuario),
        ])
        
        # Crear certificado firmado por esta CA
        ahora = datetime.now(timezone.utc)

        cert_usuario = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificado.subject)
            .public_key(clave_publica_usuario)
            .serial_number(x509.random_serial_number())
            .not_valid_before(ahora)
            .not_valid_after(ahora + timedelta(days=365))  # 1 año
            .sign(self.clave_privada, hashes.SHA256())
        )
        
        # Guardar el certificado del usuario
        cert_pem = cert_usuario.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()
        
        path = self.path_usuarios()
        cert_path = f"{path}\\{usuario}_cert.pem"
        with open(cert_path, "w", encoding="utf-8") as f:
            f.write(cert_pem)

        cert_path = f"jsons\\{usuario}\\{usuario}_cert.pem"
        with open(cert_path, "w", encoding="utf-8") as f:
            f.write(cert_pem)
        
        print(f"Certificado emitido para usuario '{usuario}'\n")
        
        return cert_usuario
    

    def cargar_desde_archivos(self):
        """Carga el certificado y la clave privada desde archivos usando crear_archivos_autoridades"""
        # Cargar certificado
        ca_path = self.determinar_raiz()
        cert_path = f"{ca_path}\\certificado.pem"
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                self.certificado = x509.load_pem_x509_certificate(f.read())
        
        # Cargar claves
        try:
            self.clave_privada = self.cargar_clave_privada()
            self.clave_publica = self.clave_privada.public_key()
        except:
            pass


def cargar_certificado(path):
    """Carga un certificado desde un archivo PEM"""
    with open(path, "rb") as f:
        cert_data = f.read()
    return x509.load_pem_x509_certificate(cert_data)