# End-to-End Encrypted Messaging System
 
Python console application that lets users register, log in and send encrypted, signed messages, backed by its own public key infrastructure (PKI). Project for the Cryptography course (Universidad Carlos III de Madrid).
 
## What's included
 
- **Custom PKI:** a root certificate authority and two subordinate CAs, with X.509 certificates issued to each user upon registration.
- **Hybrid encryption:** the message is encrypted with Fernet (symmetric key) and that key is protected with RSA-OAEP for the recipient.
- **Digital signatures:** RSA-PSS with SHA-256, verified when reading the message together with the certificate chain.
- **Passwords:** stored using Argon2 hashing.
- **Tests:** 8 `unittest` tests (self-signed root certificate, certificate chain, valid signature, tampered signature, missing certificate, etc.).
## Technologies
 
Python 3 · `cryptography` · `argon2-cffi`
 
## How to run
 
```bash
pip install -r requirements.txt
python main.py        # the first run creates the PKI automatically
python tests.py       # runs the tests
```
 
Generated data (keys, certificates and users) is stored in the `jsons/` folder, which is listed in `.gitignore` and is not uploaded to the repository.
 
## Authors
 
Team project by María Arias Rodríguez and Jaime Sánchez Sánchez.
