from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def firma_mensaje(clave_privada, mensaje):
    """Firma un mensaje con la clave privada usando RSA-PSS y SHA256"""
    if isinstance(mensaje, str):
        mensaje = mensaje.encode()
    
    firma = clave_privada.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma


def verificar_firma(clave_publica, mensaje, firma):
    """Verifica una firma digital. Retorna True si es válida, False si no"""
    try:
        if isinstance(mensaje, str):
            mensaje = mensaje.encode()
        
        clave_publica.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    
    except Exception as e:
        print(f"Verificación fallida: {e}")
        return False