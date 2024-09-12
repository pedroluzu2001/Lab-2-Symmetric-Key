from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import padding
import hashlib
import binascii
import base64

val = 'Africa'
password = 'changeme'

plaintext = val

def encrypt(plaintext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode)
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct

def decrypt(ciphertext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode)
    decryptor = cipher.decryptor()
    pl = decryptor.update(ciphertext) + decryptor.finalize()
    return pl

def pad(data, size=128):
    padder = padding.PKCS7(size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data, size=128):
    unpadder = padding.PKCS7(size).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

# Deriving the key using SHA-256 hash
key = hashlib.sha256(password.encode()).digest()

print("Before padding: ", plaintext)

# Padding the plaintext to fit the 128-bit block size
plaintext = pad(plaintext.encode())

print("After padding (CMS): ", binascii.hexlify(plaintext))

# Encrypting the padded plaintext using AES-256 in ECB mode
ciphertext = encrypt(plaintext, key, modes.ECB())
print("Cipher (ECB): ", binascii.hexlify(ciphertext))

# Decrypting the ciphertext
plaintext = decrypt(ciphertext, key, modes.ECB())

# Unpadding the plaintext
plaintext = unpad(plaintext)
print("Decrypted: ", plaintext.decode())
