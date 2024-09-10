# Lab-2-Symmetric-Key
Objective: The key objective of this lab is to understand the range of symmetric key methods 
used within symmetric key encryption. We will introduce block ciphers, stream ciphers and 
padding. The key tools used include OpenSSL, Python and JavaScript. 

# OpenSSL (0.25p)

OpenSSL is a standard tool that we used in encryption. It supports many of the standard symmetric key methods, including AES, 3DES, ChaCha20, and RC4.

##Description Result

### A.1 Use:

- `openssl list -cipher-commands`
- `openssl version`

#**Outline five encryption methods that are supported:**   
-`aes-256-ecb`  
-`aria-256-ofb`  
-`bf-ofb`   
-`camellia-256-ecb`   
-`desx` 

**Outline the version of OpenSSL:** `OpenSSL 3.2.2-dev  (Library: OpenSSL 3.2.2-dev )`


### A.2 Using openssl and the command in the form:

- `openssl prime –hex 1111`

**Check if the following are prime numbers:**

- 42 `[No]`
- 1421 `[Yes]`

### A.3 Now create a file named `myfile.txt` (either use Notepad or another editor).

Next encrypt with aes-256-cbc:

- `openssl enc -aes-256-cbc -in myfile.txt -out encrypted.bin`

and enter your password.

**Use the following command to view the output file:**

- `cat encrypted.bin`-----> Salted__����T��7�F�6z�� �RY  

**Is it easy to write out or transmit the output: [No]**

### A.4 Now repeat the previous command and add the –base64 option.

- `openssl enc -aes-256-cbc -in myfile.txt -out encrypted.bin base64`

**Use the following command to view the output file:**

- `cat encrypted.bin`----> U2FsdGVkX1+CNU/ku7bwi3K48dXINdvf4g0LggnGV7I=

**Is it easy to write out or transmit the output: [No]**

### A.5 Now Repeat the previous command and observe the encrypted output.

- `openssl enc -aes-256-cbc -in myfile.txt -out encrypted.bin base64`

**Has the output changed? [Yes]**

**Why has it changed?** Cause the behavior of base64 codification, what has changed two times. 

### A.6 Now let’s decrypt the encrypted file with the correct format:

- `openssl enc -d -aes-256-cbc -in encrypted.bin -pass pass:napier base64`

**Has the output been decrypted correctly?**
Yes

**What happens when you use the wrong password?**
Occurs an error with the decryption method

### A.7 Now encrypt a file with Blowfish and see if you can decrypt it.

**Did you manage to decrypt the file? [Yes]**

# Padding (AES) (0.25p)

With encryption, we normally use a block cipher, and where we must pad the end blocks to make sure that the data fits into a whole number of blocks. Some background material is here:

- Web link (Padding): [http://asecuritysite.com/encryption/padding](http://asecuritysite.com/encryption/padding)

## Description Result

### B.1 With AES which uses a 256-bit key, what is the normal block size (in bytes).

**Block size (bytes):** 128

**Number of hex characters for block size:** 32

### B.2 Go to:

- Web link (AES Padding): [http://asecuritysite.com/symmetric/padding](http://asecuritysite.com/symmetric/padding)

Using 256-bit AES encryption, and a message of “kettle” and a password of “oxtail”, determine the cipher using the differing padding methods (you only need to show the first six hex characters).

**CMS:**  6b6574746c650a0a0a0a0a0a0a0a0a0a

### B.3 For the following words, estimate how many hex characters will be used for the 256-bit AES encryption (do not include the inverted commas for the string to encrypt):

**Number of hex characters:**

- “fox”:32 hex characters
- “foxtrot”: 32 hex characters
- “foxtrotanteater”: 32 hex characters
- “foxtrotanteatercastle”: 64 hex characters

# Padding (DES) (0.25p)

In the first part of this lab we will investigate padding blocks:

## No Description Result

### C.1 With DES which uses a 64-bit key, what is the normal block size (in bytes): 8

**Block size (bytes):** 16

**Number of hex characters for block size:** 4

### C.2 Go to:

- Web link (DES Padding): [http://asecuritysite.com/symmetric/padding_des](http://asecuritysite.com/symmetric/padding_des)

Using 64-bit DES key encryption, and a message of “kettle” and a password of “oxtail”, determine the cipher using the differing padding methods.

**CMS:** 6b6574746c650202

### C.3 For the following words, estimate how many hex characters will be used for the 64-bit key DES encryption:

**Number of hex characters:**

- “fox”: 16 hex characters
- “foxtrot”: 16 hex characters
- “foxtrotanteater”: 32 hex characters
- “foxtrotanteatercastle”: 48 hex characters

# Python Coding (Encrypting) (1p)

In this part of the lab, we will investigate the usage of Python code to perform different padding methods and using AES. Install the necessary cryptographic libraries for AES-256 encryption. In the following we will use a 128-bit block size, and will pad the plaintext to this size with CMS, and then encryption with AES ECB. We then decrypt with the same key, and then unpad:

Run the program, and prove that it works. And identify the code which does the following:

**Generates key:** 

`key = hashlib.sha256(password.encode()).digest()`

**Pads and unpads:**
`def pad(data, size=128):
    padder = padding.PKCS7(size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data`

`def unpad(data, size=128):
    unpadder = padding.PKCS7(size).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data`

**Encrypts and decrypts:**

`def encrypt(plaintext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode)
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct`

`def decrypt(ciphertext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode)
    decryptor = cipher.decryptor()
    pl = decryptor.update(ciphertext) + decryptor.finalize()
    return pl`

### D1. Now update the code so that you can enter a string and the program will show the cipher text. The format will be something like:

- `python d_01.py hello mykey`

### Where “hello” is the plain text, and “mykey” is the key.

-`Before padding:  hello`
-`After padding (CMS):  b'68656c6c6f0b0b0b0b0b0b0b0b0b0b0b'`
-`Cipher (ECB):  b'0a7ec77951291795bac6690c9e7f4c0d'`
-`Decrypted:  hello`

Now determine the cipher text for the following (the first example has already been completed – just add the first four hex characters):

| Message   | Key        | CMS       | Cipher              |
|-----------|------------|-----------|---------------------|
| “hello”   | “hello123” |68656c6c6f0b0b0b0b0b0b0b0b0b0b0b           | 0a7e (c77951291795bac6690c9e7f4c0d) |
| “inkwell” | “orange”   |696e6b77656c6c090909090909090909           |484299ceec1ad83b1ce848b0a9733c8d                     |
| “security”| “qwerty”   |73656375726974790808080808080808           |6be35165e2c9a624de4f401692fe7161                     |
| “Africa”  | “changeme” |4166726963610a0a0a0a0a0a0a0a0a0a           |c283f9cf046e82aa6e03b9b91e19b244                     |

### D2. Now copy your code and modify it so that it implements 64-bit DES and complete the table (Ref to: [https://asecuritysite.com/symmetric/padding_des2](https://asecuritysite.com/symmetric/padding_des2)):

| Message   | Key        | CMS       | Cipher              |
|-----------|------------|-----------|---------------------|
| “hello”   | “hello123” |68656c6c6f030303           |4cd9 (24baf0c9ac60) |
| “inkwell” | “orange”   |696e6b77656c6c01           |9e0971175e4dfd5a                     |
| “security”| “qwerty”   |73656375726974790808080808080808           |c043b5bba3191fd888223899ba2bcbea                     |
| “Africa”  | “changeme” |4166726963610202           |b29d82215ae2c264                     |

Now modify the code so that the user can enter the values from the keyboard, such as with:

- `cipher=input('Enter cipher:')`
- `password=input('Enter password:')`

# Python Coding (Decrypting) (1p)

Now modify your coding for 256-bit AES ECB encryption, so that you can enter the cipher text, and an encryption key, and the code will decrypt to provide the result. You should use CMS for padding. With this, determine the plaintext for the following (note, all the plain text values are countries around the World):

| CMS Cipher (256-bit AES ECB) | Key     | Plain text |
|-------------------------------|---------|------------|
| b436bd84d16db330359edebf49725c62 | “hello” |  germany          |
| 4bb2eb68fccd6187ef8738c40de12a6b | “ankle” | spain           |
| 029c4dd71cdae632ec33e2be7674cc14 | “changeme” | england           |
| d8f11e13d25771e83898efdbad0e522c | “123456” | scotland           |

Now modify your coding for 64-bit DES ECB encryption, so that you can enter the cipher text, and an encryption key, and the code will decrypt to provide the result. You should use CMS for padding. With this, determine the plaintext for the following (note, all the plain text values are countries around the World):

| CMS Cipher (128-bit DES ECB) | Key     | Plain text |
|------------------------------|---------|------------|
| 0b8bd1e345e7bbf0 | “hello” | Germany           |
| 6ee95415aca2b33c | “ankle” |            |
| c08c3078bc88a6c3 | “changeme” |            |
| 9d69919c37c375645451d92ae15ea399 | “123456” |            |

Now update your program, so that it takes a cipher string in Base-64 and converts it to a hex string and then decrypts it. From this now decrypt the following Base-64 encoded cipher streams (which should give countries of the World):

| CMS Cipher (256-bit AES ECB) | Key     | Plain text |
|------------------------------|---------|------------|
| /vA6BD+ZXu8j6KrTHi1Y+w==    | “hello” |italy            |
| nitTRpxMhGlaRkuyXWYxtA==    | “ankle” | sweden           |
| irwjGCAu+mmdNeu6Hq6ciw==    | “changeme” |belgium            |
| 5I71KpfT6RdM/xhUJ5IKCQ==    | “123456” |mexico            |

# Stream Ciphers (1p)

## ChaCha20 and RC4

### F.1 ChaCha20

Now create a Python code for ChaCha20. Determine the cipher text for the following (the strings should be fruit names):

| Cipher | Key       | Plain text |
|--------|-----------|------------|
| e47a2bfe646a  | “qwerty”  |orange            |
| ea783afc66    | “qwerty”  |apple           |
| e96924f16d6e  | “qwerty”  |banana            |

## 1.2. What can you say about the length of the cipher stream as related to the plaintext?

The length of the cipher stream in a stream cipher like ChaCha20 is always the same as the length of the plaintext. Each byte of the plaintext is XORed with a byte from the key stream, so the cipher stream will match the plaintext in length.

## 1.3. How are we generating the key and what is the key length?

In the given code, the key is generated by hashing the passphrase "qwerty" using the SHA-256 hash function. This generates a 256-bit (32 bytes) key. ChaCha20 requires a 256-bit key, which matches this length.

## 1.4. What are the first two bytes of the key if we use a pass-phrase of “qwerty”?

If the passphrase is "qwerty", the first two bytes of the SHA-256 generated key are:  
`65e8` (hexadecimal representation of the first two bytes `0x65` and `0xe8`).

## 1.5. What is the salt (nonce) used in this code?

In the code, the nonce is a 16-byte value filled with zeros:

```python
nonce = bytes(16)  # This generates a nonce of 16 bytes, all set to zero
```

### F.2 RC4

Now create a Python code for RC4. Determine the cipher text for the following (the strings should be fruit names):

| Cipher       | Key       | Plain text |
|--------------|-----------|------------|
| 8d1cc8bdf6da | “napier”  |orange           |
| 911adbb2e6dda57cdaad | “napier”  |strawberry          |
| 8907deba     | “napier”  |kiwi            |

### 2.2. What happens to the cipher when you add an IV (salt) string?

When an IV (Initialization Vector) or salt is added to the cipher, it ensures that even if the same plaintext is encrypted multiple times with the same key, the resulting ciphertexts will be different. The IV adds randomness to the encryption process, making it harder for attackers to use known-plaintext or replay attacks. In the context of stream ciphers like RC4, adding an IV can change the initial state of the keystream generation, thereby producing a different cipher output for the same plaintext.

### 2.3. For light-weight cryptography, what is the advantage of having a variable key size?

The advantage of having a variable key size in light-weight cryptography is flexibility. Depending on the security needs and resource constraints, users can opt for a shorter key size for faster operations or a longer key size for greater security. Variable key sizes allow a balance between performance (important in resource-constrained environments like IoT devices) and security (as longer keys offer more resistance against brute-force attacks).

### 2.4. How might we change the program to implement RC4 with a 128-bit key?

To implement RC4 with a 128-bit key, you can modify the key generation process to produce a key of 128 bits (16 bytes) instead of using SHA-256, which generates a 256-bit key. Here's how you could adjust the key generation in Python:

```python
keyname = "napier"
key = hashlib.md5(keyname.encode()).digest()  # MD5 produces a 128-bit (16-byte) key 
```

### F.3 OTP and Exhaustive Search

Finally explain why an exhaustive search cannot work with OTP (One-Time Pad), even though it is unconditionally secure. 

The reason an exhaustive key search does not work against an OTP system is that it does not reduce the ambiguity of the plaintext. Every possible plaintext is equally likely, making it impossible to identify the correct one without additional information. This is the essence of OTP’s unconditional security.

# Data Encryption Standard (DES) (0.25p)

### 3.1 S-boxes in DES

Verify that the S-boxes are non-linear for the given input pairs.

### 3.2 Initial and Inverse Permutation

Show that IP−1(IP(x)) = x for the first five bits of x.

### 3.3 First Round Encryption Output

Explain what the first round encryption output should be for the given input bits.



