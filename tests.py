import unittest
import os
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from certificado import cargar_certificado
from verificador_cadenas import VerificadorCadena
from firmas import firma_mensaje, verificar_firma
from crear_usuarios import cargar_clave_publica

class TestPKI(unittest.TestCase):
    
    def get_usuarios(self):
        usuarios = []
        if os.path.exists("jsons"):
            for item in os.listdir("jsons"):
                if item != "certificados" and os.path.isdir(f"jsons/{item}"):
                    if os.path.exists(f"jsons/{item}/{item}_cert.pem"):
                        usuarios.append(item)
        return usuarios


    # Pruebas de certificados

    def test_01_certificado_raiz_autofirmado(self):
        """Test 1: Verificar que CA Raíz es autofirmada"""
        path = "jsons/certificados/CA_Raiz/certificado.pem"
        self.assertTrue(os.path.exists(path))
        
        cert = cargar_certificado(path)
        
        # Verificar que es autofirmado
        self.assertEqual(cert.subject, cert.issuer)
        
        # Verificar fechas
        ahora = datetime.now(timezone.utc)
        self.assertTrue(cert.not_valid_before_utc <= ahora <= cert.not_valid_after_utc)


    def test_02_certificados_subordinados(self):
        """Test 2: Verificar que CAs subordinadas están firmadas por Raíz"""
        cert_raiz = cargar_certificado("jsons/certificados/CA_Raiz/certificado.pem")
        subject_raiz = cert_raiz.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        verificador = VerificadorCadena()

        for nombre in ["AC_Subordinada_A", "AC_Subordinada_B"]:
            path = f"jsons/certificados/CA_Raiz/{nombre}/certificado.pem"
            self.assertTrue(os.path.exists(path))
            
            cert_sub = cargar_certificado(path)
            
            # Verificar Emisor
            cn = cert_sub.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            self.assertEqual(cn, subject_raiz)
            
            # Verificar firma
            self.assertTrue(verificador.verificar_firma_certificado(cert_sub, cert_raiz))


    def test_03_cadena_completa_usuarios(self):
        """Test 3: Verificar cadenas de certificados completas"""
        verificador = VerificadorCadena()
        for usuario in self.get_usuarios():
            valido, _ = verificador.verificar_cadena_completa(usuario)
            self.assertTrue(valido)


    # Pruebas de firmas

    def test_04_firma_basica(self):
        """Test 4: Firmar y verificar un mensaje simple"""
        # Generar claves
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        mensaje = b"Hola mundo"
        firma = firma_mensaje(private_key, mensaje)
        
        # Verificar correcta
        self.assertTrue(verificar_firma(public_key, mensaje, firma))
        
        # Verificar incorrecta (mensaje alterado)
        self.assertFalse(verificar_firma(public_key, b"Hola mundo 2", firma))


    def test_05_integridad_claves_usuario(self):
        """Test 5: Asegura que la clave pública almacenada en el 
        certificado del usuario es, efectivamente, su clave pública"""
        usuarios = self.get_usuarios()
        if not usuarios: return
            
        usuario = usuarios[0]
        cert = cargar_certificado(f"jsons/{usuario}/{usuario}_cert.pem")
        
        # Clave del certificado
        pub_cert = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Clave del archivo
        pub_file = cargar_clave_publica(usuario).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self.assertEqual(pub_cert, pub_file)


    def test_06_integridad_firma_manipulada(self):
        """Test 6: Verificar integridad de firmas en sistema de mensajes"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        mensaje = b"Datos"
        firma = bytearray(firma_mensaje(private_key, mensaje))
        
        # Romper la firma
        firma[0] = (firma[0] + 1) % 256
        
        self.assertFalse(verificar_firma(public_key, mensaje, bytes(firma)))


    #  Errores y casos límite

    def test_07_certificado_inexistente(self):
        """Test 7: Manejar certificados inexistentes"""
        verificador = VerificadorCadena()
        valido, _ = verificador.verificar_cadena_completa("usuario_falso")
        self.assertFalse(valido)


    def test_08_verificar_desde_pem(self):
        """Test 8: Verificar certificado desde contenido PEM"""
        usuarios = self.get_usuarios()
        if not usuarios: return
            
        usuario = usuarios[0]
        with open(f"jsons/{usuario}/{usuario}_cert.pem", "r") as f:
            pem = f.read()
            
        verificador = VerificadorCadena()
        valido, _ = verificador.verificar_certificado_desde_pem(pem, usuario)
        self.assertTrue(valido)


if __name__ == '__main__':
    unittest.main()