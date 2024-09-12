from Crypto.Cipher import AES
import hashlib
import base64
import binascii
from Crypto.Util.Padding import unpa
v

def decrypt(ciphertext, key, mode):
    encobj = AES.new(key, mode)
    return encobj.decrypt(ciphertext)

def remove_padding(data, block_size):
    try:
        return unpad(data, block_size)
    except ValueError as e:
        print("Padding error:", e)
        return None

def base64_to_hex(base64_string):
    raw_bytes = base64.b64decode(base64_string)
    hex_string = binascii.hexlify(raw_bytes).decode('utf-8')
    return raw_bytes, hex_string

# Decrypt function with base64 input
def decrypt_base64_aes(cipher_b64, password):
    print(f"Ciphertext (Base64): {cipher_b64}")

    # Step 1: Convert Base64 to raw bytes and hex
    ciphertext_bytes, ciphertext_hex = base64_to_hex(cipher_b64)
    print(f"Ciphertext (Hex): {ciphertext_hex}")
    
    # Step 2: Generate the AES key (256-bit from password)
    key = hashlib.sha256(password.encode()).digest()

    # Step 3: Decrypt the ciphertext
    plaintext_padded = decrypt(ciphertext_bytes, key, AES.MODE_ECB)

    # Step 4: Remove padding and decode
    plaintext = remove_padding(plaintext_padded, AES.block_size)
    
    if plaintext:
        print("Decrypted text:", plaintext.decode())
    else:
        print("Failed to remove padding")

# Test data
test_data = [
    ("/vA6BD+ZXu8j6KrTHi1Y+w==", "hello"),
    ("nitTRpxMhGlaRkuyXWYxtA==", "ankle"),
    ("irwjGCAu+mmdNeu6Hq6ciw==", "changeme"),
    ("5I71KpfT6RdM/xhUJ5IKCQ==", "123456")
]

# Test decryption for each pair of cipher and password
for cipher_b64, password in test_data:
    print(f"\n--- Decrypting with password: {password} ---")
    decrypt_base64_aes(cipher_b64, password)
