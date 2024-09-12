import hashlib
from Crypto.Cipher import ARC4  # ARC4 es el RC4 en la librería PyCryptodome
import base64

# Generar la clave usando SHA-256
keyname = "napier"
key = hashlib.sha256(keyname.encode()).digest()

# Texto cifrado en hexadecimal
ciphertext = "8907deba"
print("Ciphertext:\t", ciphertext)

# Descifrar el texto cifrado con RC4
cipher = ARC4.new(key)
decrypted_text = cipher.decrypt(bytes.fromhex(ciphertext))

# Imprimir el resultado en texto
print("Deciphered text:\t", decrypted_text.decode('utf-8', errors='ignore'))


