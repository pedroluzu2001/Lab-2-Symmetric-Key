from Crypto.Cipher import DES
import hashlib
import binascii
from Crypto.Util.Padding import unpad
import base64

password = 'changeme'

def encrypt(plaintext, key, mode):
    encobj = DES.new(key, mode)
    return encobj.encrypt(plaintext)

def decrypt(ciphertext, key, mode):
    encobj = DES.new(key, mode)
    return encobj.decrypt(ciphertext)

def remove_padding(data, block_size):
    try:
        return unpad(data, block_size)
    except ValueError as e:
        print("Padding error:", e)
        return None

key = hashlib.sha256(password.encode()).digest()

# Ajusta el texto cifrado y la contraseña para las pruebas
ciphertext = binascii.unhexlify("c08c3078bc88a6c3")

# Descifrar
plaintext = decrypt(ciphertext, key[:8], DES.MODE_ECB)

# Eliminar padding
plaintext = remove_padding(plaintext, DES.block_size)

if plaintext:
    print("Decrypted:", plaintext.decode())
else:
    print("Failed to remove padding")
