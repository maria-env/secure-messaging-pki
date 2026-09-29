from certificado import AutoridadCertificacion

def inicializar_pki():
    """Inicializa la infraestructura de clave pública (PKI) con múltiples ACs subordinadas"""
    
    print("\n=== Inicializando PKI ===\n")
    
    # Crear CA Raíz
    print("[1/4] Creando Autoridad de Certificación Raíz...")
    ca_raiz = AutoridadCertificacion(nombre="CA_Raiz", es_raiz=True)
    ca_raiz.crear_certificado_raiz()
    
    # Crear AC Subordinada A
    print("\n[2/4] Creando Autoridad de Certificación Subordinada A...")
    ac_a = AutoridadCertificacion(
        nombre="AC_Subordinada_A",
        es_raiz=False,
        ca_superior=ca_raiz
    )
    ca_raiz.crear_certificado_subordinado(ac_a)
    
    # Crear AC Subordinada B
    print("\n[3/4] Creando Autoridad de Certificación Subordinada B...")
    ac_b = AutoridadCertificacion(
        nombre="AC_Subordinada_B",
        es_raiz=False,
        ca_superior=ca_raiz
    )
    ca_raiz.crear_certificado_subordinado(ac_b)
    
    print("\n[4/4] PKI inicializada correctamente")
    print("\nJerarquía creada:")
    print("  CA_Raiz (Autoridad Raíz)")
    print("  ├── AC_Subordinada_A")
    print("  |── AC_Subordinada_B")
    print("\nCada AC subordinada puede emitir certificados a usuarios\n")

if __name__ == "__main__":
    inicializar_pki()