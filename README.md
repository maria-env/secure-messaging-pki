# Sistema de mensajería cifrado extremo a extremo

Aplicación de consola en Python que permite registrar usuarios, iniciar sesión y enviar mensajes cifrados y firmados, apoyada en una infraestructura de clave pública (PKI) propia. Proyecto de la asignatura de Criptografía (Universidad Carlos III de Madrid).

## Qué incluye

- **PKI propia:** una autoridad de certificación raíz y dos subordinadas, con certificados X.509 emitidos a cada usuario al registrarse.
- **Cifrado híbrido:** el mensaje se cifra con Fernet (clave simétrica) y esa clave se protege con RSA-OAEP para el destinatario.
- **Firmas digitales:** RSA-PSS con SHA-256, verificadas al leer el mensaje junto con la cadena de certificados.
- **Contraseñas:** almacenadas con hash Argon2.
- **Pruebas:** 8 tests con `unittest` (certificado raíz autofirmado, cadena de certificados, firma válida, firma manipulada, certificado inexistente, etc.).

## Tecnologías

Python 3 · `cryptography` · `argon2-cffi`

## Cómo ejecutarlo

```bash
pip install -r requirements.txt
python main.py        # la primera vez crea la PKI automáticamente
python tests.py       # ejecuta las pruebas
```

Los datos generados (claves, certificados y usuarios) se guardan en la carpeta `jsons/`, que está en el `.gitignore` y no se sube al repositorio.

## Autoría

Trabajo en equipo de 2 personas: María Arias Rodríguez y Jaime Sánchez Sánchez.
