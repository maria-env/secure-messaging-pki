from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from certificado import cargar_certificado
import os
from datetime import datetime, timezone

class VerificadorCadena:
    """Verifica la cadena completa de certificados desde el usuario hasta la CA raíz"""
    
    def __init__(self):
        self.ca_raiz_cert = None
        self.nombre_ca_raiz = None
        self._cargar_ca_raiz()
    

    def _cargar_ca_raiz(self):
        """Carga el certificado de la CA raíz"""
        try:
            cert_dir = "jsons\\certificados"
            
            if not os.path.exists(cert_dir):
                print("No existe la carpeta de certificados")
                return
            
            # Buscar la raíz
            carpetas_raiz = [d for d in os.listdir(cert_dir) 
                           if os.path.isdir(os.path.join(cert_dir, d))]
            
            if not carpetas_raiz:
                print("No se encontró ninguna carpeta raíz")
                return
            
            # Tomar la primera carpeta como raíz
            self.nombre_ca_raiz = carpetas_raiz[0]
            cert_path = os.path.join(cert_dir, self.nombre_ca_raiz, "certificado.pem")

            if os.path.exists(cert_path):
                self.ca_raiz_cert = cargar_certificado(cert_path)
            else:
                print("No se encontró el certificado de la autoridad raíz")
        except Exception as e:
            print(f"Error al cargar la autoridad raíz: {e}")
    

    def verificar_firma_certificado(self, cert_firmado, cert_emisor):
        """Verifica que cert_firmado fue realmente firmado por cert_emisor"""
        try:
            clave_publica_emisor = cert_emisor.public_key()
            
            clave_publica_emisor.verify(
                cert_firmado.signature,
                cert_firmado.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_firmado.signature_hash_algorithm
            )
            return True
        except Exception:
            return False
    
    
    def verificar_fechas(self, cert):
        """Verifica que el certificado no esté expirado"""
        ahora = datetime.now(timezone.utc)
        
        if not (cert.not_valid_before_utc <= ahora <= cert.not_valid_after_utc):
            return False
        return True
    

    def obtener_nombre_ac_emisora(self, cert_usuario):
        """Extrae el nombre de la AC que emitió el certificado del usuario"""
        issuer_cn = cert_usuario.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if issuer_cn:
            return issuer_cn[0].value
        return None
    

    def cargar_certificado_ac(self, nombre_ac):
        """Carga el certificado de una AC subordinada por su nombre"""
        try:
            cert_dir = "jsons\\certificados"
            
            if not os.path.exists(cert_dir):
                return None
            
            carpetas_raiz = [d for d in os.listdir(cert_dir) 
                           if os.path.isdir(os.path.join(cert_dir, d))]
            
            if not carpetas_raiz:
                return None
            
            nombre_ca_raiz = carpetas_raiz[0]
            ca_raiz_path = os.path.join(cert_dir, nombre_ca_raiz)

            cert_path = os.path.join(ca_raiz_path, nombre_ac, "certificado.pem")
            if os.path.exists(cert_path):
                return cargar_certificado(cert_path)
            else:
                return None
                
        except Exception as e:
            print(f"Error al cargar {nombre_ac}: {e}")
            return None
    

    def verificar_cadena_completa(self, usuario):
        """Verifica la cadena completa de certificados
        Usuario -> CA Subordinada -> CA Raíz"""
        if not self.ca_raiz_cert:
            return False, "CA Raíz no disponible\n"
        
        print(f"Verificando cadena de certificados para '{usuario}'\n")
        
        # Cargar certificado del usuario
        cert_usuario_path = f"jsons\\{usuario}\\{usuario}_cert.pem"
        if not os.path.exists(cert_usuario_path):
            return False, f"No existe certificado para {usuario}\n"
        
        cert_usuario = cargar_certificado(cert_usuario_path)
        print(f"Certificado de usuario '{usuario}' cargado\n")
        
        return self._verificar_cert(cert_usuario, usuario)
    

    def verificar_certificado_desde_pem(self, certificado_pem, nombre_esperado):
        """Verifica un certificado desde su contenido PEM"""
        if not self.ca_raiz_cert:
            return False, "Autoridad raíz no disponible\n"
        
        try:
            cert_usuario = x509.load_pem_x509_certificate(certificado_pem.encode())
            
            # Verificar nombre
            cn_attrs = cert_usuario.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            nombre_real = cn_attrs[0].value if cn_attrs else None
            
            if nombre_real != nombre_esperado:
                return False, f"Certificado no corresponde a '{nombre_esperado}'\n"
            
            return self._verificar_cert(cert_usuario, nombre_esperado)
            
        except Exception as e:
            return False, f"Error al procesar certificado: {e}\n"
    

    def _verificar_cert(self, cert_usuario, nombre_usuario):
        """Verifica un certificado"""
        
        # Verificar fechas del usuario
        if not self.verificar_fechas(cert_usuario):
            return False, "Certificado de usuario expirado\n"
        
        # Identificar AC emisora
        nombre_ac_emisora = self.obtener_nombre_ac_emisora(cert_usuario)
        if not nombre_ac_emisora:
            return False, "No se pudo identificar CA emisora\n"
        
        cert_ac_subordinada = self.cargar_certificado_ac(nombre_ac_emisora)
        if not cert_ac_subordinada:
            return False, f"No se pudo cargar certificado de {nombre_ac_emisora}\n"
        
        # Verificar firma de AC sobre certificado de usuario
        if not self.verificar_firma_certificado(cert_usuario, cert_ac_subordinada):
            return False, f"Certificado no firmado por {nombre_ac_emisora}\n"
        
        # Verificar fechas de AC
        if not self.verificar_fechas(cert_ac_subordinada):
            return False, f"Certificado de {nombre_ac_emisora} expirado\n"
        
        if not self.verificar_firma_certificado(cert_ac_subordinada, self.ca_raiz_cert):
            return False, f"{nombre_ac_emisora} no firmada por {self.nombre_ca_raiz}\n"
        
        # Verificar autofirma de CA Raíz
        if not self.verificar_firma_certificado(self.ca_raiz_cert, self.ca_raiz_cert):
            return False, f"{self.nombre_ca_raiz} no está autofirmada correctamente\n"
        
        # Verificar fechas de CA Raíz
        if not self.verificar_fechas(self.ca_raiz_cert):
            return False, f"Certificado de {self.nombre_ca_raiz} expirado\n"
        
        return True, f"Cadena válida: {nombre_usuario} <- {nombre_ac_emisora} <- {self.nombre_ca_raiz}\n"