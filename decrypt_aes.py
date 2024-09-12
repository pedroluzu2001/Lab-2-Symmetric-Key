from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import hashlib
import binascii

# Solicitar la clave y el texto cifrado como entrada del usuario
ciphertext_hex = input('Enter ciphertext (in hex): ')
password = input('Enter password: ')

# Convertir el texto cifrado de hex a bytes
ciphertext = binascii.unhexlify(ciphertext_hex)

# Función para descifrar usando AES-256 en modo ECB
def decrypt(ciphertext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode)
    decryptor = cipher.decryptor()
    pl = decryptor.update(ciphertext) + decryptor.finalize()
    return pl

# Función para eliminar el padding
def unpad(data, size=128):
    unpadder = padding.PKCS7(size).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

# Derivar la clave usando un hash SHA-256
key = hashlib.sha256(password.encode()).digest()

# Imprimir el texto cifrado ingresado
print("Ciphertext (ECB) in bytes: ", ciphertext)

# Descifrar el texto cifrado
plaintext = decrypt(ciphertext, key, modes.ECB())

# Eliminar el padding del texto descifrado
plaintext = unpad(plaintext)

# Mostrar el texto descifrado
print("Decrypted: ", plaintext.decode())
