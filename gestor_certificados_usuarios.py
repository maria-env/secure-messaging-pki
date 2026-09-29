from certificado import AutoridadCertificacion, cargar_certificado
from crear_usuarios import cargar_clave_publica
from verificador_cadenas import VerificadorCadena
import os
from cryptography import x509
import random

class GestorCertificadosUsuarios:
    """Gestiona la emisión y verificación de certificados de usuarios con múltiples ACs"""
    
    def __init__(self):
        self.acs_subordinadas = {}  # Diccionario de autoridades subordinadas
        
        # Cargamos las autoridades subordinadas en el diccionario
        self._cargar_cas()
    

    def _cargar_cas(self):
        """Carga todas las CAs disponibles"""
        try:
            cert_dir = "jsons\\certificados"
            
            if not os.path.exists(cert_dir):
                print("No existe la carpeta de certificados\n")
                return
            
            # Buscar la raíz
            carpetas_raiz = [d for d in os.listdir(cert_dir) 
                           if os.path.isdir(os.path.join(cert_dir, d))]
            
            if not carpetas_raiz:
                print("No se encontró ninguna carpeta raíz\n")
                return
            
            # Tomar la primera carpeta como raíz (solo hay una)
            nombre_ca_raiz = carpetas_raiz[0]
            ca_raiz_path = os.path.join(cert_dir, nombre_ca_raiz)
            
            # Cargar autoridad raíz (se usará más adelante)
            ca_raiz = AutoridadCertificacion(nombre=nombre_ca_raiz, es_raiz=True)
            
            # Buscar autoridades subordinadas dentro de la carpeta de la raíz
            carpetas_subordinadas = [d for d in os.listdir(ca_raiz_path) 
                                    if os.path.isdir(os.path.join(ca_raiz_path, d))]
            
            if not carpetas_subordinadas:
                print("No se encontraron autoridades subordinadas\n")
                return
            
            # Cargar cada CA subordinada
            for nombre_ac_sub in carpetas_subordinadas:
                ac_sub_path = os.path.join(ca_raiz_path, nombre_ac_sub)
                cert_sub_file = os.path.join(ac_sub_path, "certificado.pem")
                
                # Verificar que existe el certificado
                if os.path.exists(cert_sub_file):
                    ac = AutoridadCertificacion(
                        nombre=nombre_ac_sub,
                        es_raiz=False,
                        ca_superior=ca_raiz
                    )
                    ac.cargar_desde_archivos()
                    self.acs_subordinadas[nombre_ac_sub] = ac
                    print(f"Autoridad subordinada '{nombre_ac_sub}' cargada\n")
                else:
                    print(f"No se encontró certificado en {ac_sub_path}\n")
            
            if not self.acs_subordinadas:
                print("No se cargaron las autoridades subordinadas válidas\n")
                
        except Exception as e:
            print(f"Error al cargar autoridades: {e}\n")
    

    def emitir_certificado_a_usuario(self, usuario):
        """Emite un certificado a un usuario desde una AC específica
        Si no se especifica AC, usa la primera disponible"""
        if not self.acs_subordinadas:
            print("No hay autoridades subordinadas disponibles\n")
            return False
        
        # Elegir una AC subordinada aleatoria
        nombre_ac = random.choice(list(self.acs_subordinadas.keys()))
        
        try:
            # Cargar la clave pública del usuario
            clave_publica = cargar_clave_publica(usuario)
            
            # Emitir certificado desde la AC especificada
            ac = self.acs_subordinadas[nombre_ac]
            ac.emitir_certificado_usuario(usuario, clave_publica)

            print(f"Certificado emitido para '{usuario}' por '{nombre_ac}'\n")
            return True
        except Exception as e:
            print(f"Error al emitir certificado: {e}\n")
            return False
    

    def verificar_certificado_usuario(self, usuario):
        """Verifica la cadena completa de certificados del usuario
            Usuario -> CA Subordinada -> CA Raíz"""
        verificador = VerificadorCadena()

        valido, mensaje = verificador.verificar_cadena_completa(usuario)
        
        if not valido:
            print(f"Certificado no válido: {mensaje}\n")
        
        return valido
    

    def obtener_certificado_usuario(self, usuario):
        """Obtiene el certificado de un usuario"""
        try:
            cert_path = f"jsons\\{usuario}\\{usuario}_cert.pem"
            if os.path.exists(cert_path):
                return cargar_certificado(cert_path)
            return None
        except Exception as e:
            print(f"Error al cargar certificado: {e}\n")
            return None
    

    def obtener_info_certificado(self, usuario):
        """Obtiene información detallada del certificado de un usuario"""
        cert = self.obtener_certificado_usuario(usuario)
        if not cert:
            return None
        
        # Extraer el nombre de la AC emisora
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        nombre_ac = issuer_cn[0].value if issuer_cn else "Desconocida\n"
        
        return {
            "usuario": usuario,
            "emitido_por": nombre_ac,
            "valido_desde": cert.not_valid_before_utc,
            "valido_hasta": cert.not_valid_after_utc,
            "numero_serie": cert.serial_number
        }