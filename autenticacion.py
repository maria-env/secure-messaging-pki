from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
import re
from datetime import datetime
from funciones_json import load_json, save_json, initialize_files
from crear_usuarios import initialize_folder
from encriptado_hibrido import CifradoHibrido

USERS_FILE = r"jsons\users.json"

class SistemaAutenticacion:
    """Gestiona el registro y autenticación de usuarios"""
    
    def __init__(self, users_file = USERS_FILE):
        """Inicializa el sistema de autenticación con Argon2"""
        self.users_file = users_file
        
        # Inicializamos archivos si no existen
        initialize_files()

        self.ph = PasswordHasher()
        
        self.users_db = load_json(self.users_file)
        
        print("Sistema de Autenticación inicializado\n")
    
    
    def _validar_usuario(self, usuario):
        """Valida el formato del nombre de usuario"""
        
        # Si no hay nombre de usuario, devuelve False
        if not usuario or len(usuario) == 0:
            print("El nombre de usuario no puede estar vacío")
            return False
        
        # Si el nombre de usuario tiene menos de 3 caracteres, devuelve False
        if len(usuario) < 3:
            print("El nombre de usuario debe tener al menos 3 caracteres")
            return False
        
        # Si el nombre de usuario tiene más de 20 caracteres, devuelve False
        if len(usuario) > 20:
            print("El nombre de usuario no puede exceder 20 caracteres")
            return False
        
        # Si el nombre de usuario no contiene únicamente letras, números, y guión bajo, devuelve False
        if not re.match(r'^[A-Z0-9_]', usuario):
            print("El nombre de usuario solo puede contener letras, números y guiones bajos")
            return False
        
        # En los demás casos devuelve True
        return True
    

    def _validar_contraseña(self, contraseña):
        """Valida que el usuario tenga una contraseña segura"""

        # Si no introduce una contraseña, devuelve False
        if not contraseña or len(contraseña) == 0:
            print("La contraseña no puede estar vacía")
            return False
        
        # Si la contraseña tiene una longitud inferior a 8 caracteres, devuelve False
        if len(contraseña) < 8:
            print("La contraseña debe tener al menos 8 caracteres")
            return False
        
        # Si la contraseña no contiene una mayúscula, devuelve False
        if not re.search(r'[A-Z]', contraseña):
            print("La contraseña debe contener al menos una mayúscula")
            return False
        
        # Si la contraseña no contiene una minúscula, devuelve False
        if not re.search(r'[a-z]', contraseña):
            print("La contraseña debe contener al menos una minúscula")
            return False
        
        # Si la contraseña no contiene un número, devuelve False
        if not re.search(r'[0-9]', contraseña):
            print("La contraseña debe contener al menos un número")
            return False
        
        # Si la contraseña no contiene un carácter especial, devuelve False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]]', contraseña):
            print("La contraseña debe contener al menos un carácter especial")
            return False
        
        return True
    

    def registrar_usuario(self, usuario, contraseña):
        """Registra un nuevo usuario en el sistema"""

        # Validamos nombre de usuario
        valido = self._validar_usuario(usuario)
        if not valido:
            return False
        
        # Verificamos si el usuario ya existe
        if usuario in self.users_db:
            print(f"Usuario '{usuario}' ya existe")
            return False
        
        # Validamos seguridad de la contraseña
        valido = self._validar_contraseña(contraseña)
        if not valido:
            return False
        
        # Hacemos hash a la contraseña usando Argon2
        try:
            contraseña_hash = self.ph.hash(usuario + contraseña)
        except Exception as e:
            print(f"Error al hacer hash a la contraseña: {e}")
            return False
        
        # Creamos registro de usuario
        self.users_db[usuario] = {
            'hash': contraseña_hash,
            'fecha_creacion': datetime.now().isoformat(),
            'ultimo_login': None
        }
        
        # Guardamos el json con el nuevo usuario
        save_json(self.users_file, self.users_db)

        #Creamos carpeta y archivos del usuario

        initialize_folder(usuario)

        # Generamos claves
        cripto = CifradoHibrido()
        cripto.generar_claves(usuario, contraseña)

        
        print("Usuario registrado correctamente\n")
        print(f"   - Usuario: {usuario}\n")
        
        return True
    

    def login(self, usuario, contraseña):
        """Inicia sesión de un usuario asegurándose de que la información introducida es correcta"""

        return self.autenticar_usuario(usuario, contraseña)
    

    def autenticar_usuario(self, usuario, contraseña):
        """Autentifica un usuario verificando sus credenciales con Argon2"""

        # Cargamos el json de usuarios
        self.users_db = load_json(self.users_file)
        
        # Verificamos si el usuario ya existe
        if usuario not in self.users_db:
            print(f"Usuario '{usuario}' no existe")
            return False
        
        # Obtenemos el hash almacenado
        hash_almacenado = self.users_db[usuario]['hash']
        
        # Verificamos la contraseña con Argon2
        try:
            self.ph.verify(hash_almacenado, usuario + contraseña) 
            
            # Actualizamos último login
            self.users_db[usuario]['ultimo_login'] = datetime.now().isoformat()
            save_json(self.users_file, self.users_db)
            
            print(f"Autenticación correcta\n")
            print(f"   - Usuario: {usuario}\n")
            
            return True
        
        # Si la verificación falla, se lanza VerifyMismatchError (excepción de la biblioteca de argon)
        except VerifyMismatchError:
            print(f"Contraseña incorrecta para usuario '{usuario}'")
            return False
        
        # Si hay otro error en la verificación, se lanza VerificationError o InvalidHash
        except (VerificationError, InvalidHash) as e:
            print(f"Error en verificación: {e}")
            return False


    def existe_usuario(self, usuario):
        """Verifica si un usuario existe en el sistema"""

        # Cargamos el json de usuarios, y devuelve el usuario si es que existe
        self.users_db = load_json(self.users_file)
        return usuario in self.users_db
