from autenticacion import SistemaAutenticacion
from encriptado_hibrido import CifradoHibrido
from gestor_certificados_usuarios import GestorCertificadosUsuarios
from inicializar_pki import inicializar_pki
import getpass
import os

def menu_principal():
    print("====================================")
    print("   Sistema de Mensajería Segura  ")
    print("====================================\n")
    print("1. Registrar nuevo usuario")
    print("2. Iniciar sesión")
    print("3. Salir")

def menu_usuario(username):
    print(f"\n=== Menú del usuario: {username} ===")
    print("1. Enviar mensaje cifrado")
    print("2. Leer mis mensajes recibidos")
    print("3. Ver información de mi certificado")
    print("4. Cerrar sesión")

def main():
    # Verificar que existe la PKI
    if not os.path.exists("jsons\\certificados"):
        inicializar_pki()
    
    autenticacion = SistemaAutenticacion()
    cripto = CifradoHibrido()
    gestor_certs = GestorCertificadosUsuarios()

    while True:
        menu_principal()
        opcion = input("Selecciona una opción: ").strip()

        # Registro
        if opcion == "1":
            usuario = input("Nombre de usuario: ").strip()
            contraseña = getpass.getpass("Contraseña: ").strip()

            if autenticacion.registrar_usuario(usuario, contraseña):
                print(f"\nEmitiendo certificado para '{usuario}'...")
                gestor_certs.emitir_certificado_a_usuario(usuario)
                print("\nUsuario registrado correctamente con certificado.\n")
            else:
                print("No se pudo registrar el usuario.\n")

        # Login
        elif opcion == "2":
            usuario = input("Usuario: ").strip()
            contraseña = getpass.getpass("Contraseña: ").strip()

            if autenticacion.login(usuario, contraseña):
                print(f"\n¡Bienvenido, {usuario}!")
                menu_sesion(autenticacion, cripto, gestor_certs, usuario, contraseña)
            else:
                print("\nError en el login.\n")

        # Salida
        elif opcion == "3":
            print("Saliendo del programa...")
            break

        else:
            print("Opción no válida. Intenta de nuevo.\n")

def menu_sesion(autenticacion, cripto, gestor_certs, usuario, contraseña):
    while True:
        menu_usuario(usuario)
        opcion = input("Selecciona una opción: ").strip()

        # Enviar mensaje
        if opcion == "1":
            receptor = input("Destinatario: ").strip()
            
            if not autenticacion.existe_usuario(receptor):
                print(f"El usuario '{receptor}' no existe.\n")
                continue
            
            mensaje = input("Mensaje: ").strip()
            cripto.encriptado_hibrido(usuario, receptor, mensaje, contraseña)

        # Leer mensajes
        elif opcion == "2":
            cripto.desencriptado_hibrido(usuario, contraseña)

        # Ver certificado
        elif opcion == "3":
            info = gestor_certs.obtener_info_certificado(usuario)
            if info:
                print(f"\n--- Certificado de {info['usuario']} ---")
                print(f"Emitido por: {info['emitido_por']}")
                print(f"Válido desde: {info['valido_desde']}")
                print(f"Válido hasta: {info['valido_hasta']}")
                print(f"Número de serie: {info['numero_serie']}\n")
            else:
                print("No se pudo obtener información del certificado.\n")

        # Cerrar sesión
        elif opcion == "4":
            print(f"Sesión cerrada para {usuario}.\n")
            break

        else:
            print("Opción no válida. Intenta de nuevo.\n")

if __name__ == "__main__":
    main()