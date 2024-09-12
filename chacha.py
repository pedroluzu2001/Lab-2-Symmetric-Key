import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
import base64

# Definir el nombre de la clave
keyname = "qwerty"

# Generar la clave utilizando SHA-256
key = hashlib.sha256(keyname.encode()).digest()

# Crear el nonce (16 bytes)
nonce = bytes(16)  # 16 bytes para el nonce, rellenos de ceros

# Convertir el texto cifrado de hexadecimal a bytes
#ciphertext = bytes.fromhex("e47a2bfe646a")
#ciphertext = bytes.fromhex("ea783afc66")
ciphertext = bytes.fromhex("e96924f16d6e")

print("Clave generada (SHA-256):", key)
print("Ciphertext (en hexadecimal):", ciphertext.hex())

# Inicializar el objeto de cifrado ChaCha20
cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
decryptor = cipher.decryptor()

# Desencriptar el texto cifrado
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# Mostrar el texto descifrado en UTF-8
print("Texto descifrado:", plaintext.decode('utf-8', errors='replace'))  # Intentar decodificar el texto plano
