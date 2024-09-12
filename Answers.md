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

## Data Encryption Standard (DES)

### 3.1. S-Boxes Nonlinearity
Show that S1(x1)⊕S1(x2) is not equal to S1(x1 ⊕ x2):
- a. For x1 = 000000 and x2 = 000001.
- b. For x1 = 111111 and x2 = 100000.
- c. For x1 = 101010 and x2 = 010101.

### Case (A)
For S1(x1 ⊕  x2)= 00000.

And S1(x1) ⊕ S1(x2) = 001110.

*Then: S1(x1 ⊕  x2)= 00000 is not equal to S1(x1) ⊕ S1(x2) = 001110* 

### Case (B)
- **Inputs**:
  -x1 = 111111 
  -x2 = 100000 

- **Results**:
  -  S1(x1 ⊕ x2) = 1100 
  -  S1(x1) ⊕ S1(x2) = 101011 

*Then: S1(x1 ⊕ x2) = 1100 is not equal to S1(x1) ⊕ S1(x2) = 101011*

---

### Case (C)
- **Inputs**:
  -  x1 = 101010
  -  x2 = 010101

- **Results**:
  -S1(x1 ⊕ x2) = 0111 
  -S1(x1) ⊕ S1(x2) = 110101

*Then: S1(x1 ⊕ x2) = 0111  is not equal to S1(x1) ⊕ S1(x2) = 110101*





### 3.2. Inverse Operations of IP
# Verification of Inverse Permutation in DES

We want to verify that the initial permutation (IP) and its inverse (IP⁻¹) are truly inverse operations. We consider a vector `x = (x1, x2,...,x64)` of 64 bits. The goal is to show that:

1. **Apply the initial permutation (IP)**:  
   Let `y = IP(x) = (y1, y2,...,y64)`.  
   The permutation reorders the bits as follows:
   - `y40 = x1`
   - `y8 = x2`
   - `y48 = x3`
   - `y16 = x4`
   - `y56 = x5`

2. **Apply the inverse permutation (IP⁻¹)**:  
   Now, applying `IP⁻¹(y)` reverts the reordering. For the first five bits, we have:
   IP⁻¹(y)=(y40, y8, y48, y16, y56,...) = (x1, x2, x3, x4, x5,...)

   
Since `y40 = x1`, `y8 = x2`, `y48 = x3`, `y16 = x4`, and `y56 = x5`, we conclude that:


  IP⁻¹(IP(y))= (x1, x2, x3, x4, x5,...)

  
Thus, the inverse permutation `IP⁻¹` correctly restores the original vector `x`

### 3.3. Output of the First Round of DES (All Zeros)
What is the output of the first round of the DES algorithm when both the plaintext and the key are all zeros?

- **Plaintext**: All zeros (`000000...000000`)
- **Key**: All zeros (`000000...000000`)
## 1. Initial Permutation (IP)
- **Plaintext (x)**: All bits set to zero `(x = 0, 0, 0,...,0)`.
- Since all bits are equal, applying the initial permutation `IP(x)` does not change the plaintext:
  - `IP(x) = x`

## 2. Initial Splitting (L0 and R0)
- After `IP(x) = x`, both the left half `L0` and the right half `R0` of the plaintext are composed of all-zero bits:
  - `L0 = 0, 0, 0,...,0`
  - `R0 = 0, 0, 0,...,0`

## 3. Key Generation - PC-1
- **Key (k)**: All bits set to zero `(k = 0, 0, 0,...,0)`.
- Applying `PC-1` to the key results in 56 zero bits:
  - `L = 0, 0, 0,...,0`

## 4. Key Transformation
- **Transform 1**: Rotates the two halves of `L` by one bit. Since `L` is all zeros, the result is unchanged:
  - `L = 0, 0, 0,...,0`
- **PC-2**: Permutation operation that results in `k1` as 48 zero bits:
  - `k1 = 0, 0, 0,...,0`

## 5. Function f (First Round)
1. **Expansion Permutation**:
   - Expands `R0` (which is all zeros) into 48 zero bits:
     - `y = 0, 0, 0,...,0`
   
2. **XOR Operation**:
   - Performs XOR between `y` and `k1` (both are zero arrays):
     - `z = 0, 0, 0,...,0`

3. **S-Box Application**:
   - Divides `z` into 8 blocks of 6 bits (all zeros) and applies the S-boxes:
     - `S1: 000000 → 1110 (14 in decimal)`
     - `S2: 000000 → 1111 (15 in decimal)`
     - `S3: 000000 → 1010 (10 in decimal)`
     - `S4: 000000 → 0111 (07 in decimal)`
     - `S5: 000000 → 0010 (02 in decimal)`
     - `S6: 000000 → 1100 (12 in decimal)`
     - `S7: 000000 → 0100 (04 in decimal)`
     - `S8: 000000 → 1101 (13 in decimal)`
   - **Result** after S-boxes:  
     `11101111101001110010110001001101`

4. **Permutation**:
   - Applies a permutation on the result from the S-boxes:
     - **Result** after permutation:  
       `11011000110110001101111110111100`

5. **XOR with L0**:
   - Performs XOR between the permuted result and `L0` (which is all zeros):
     - **Result**:  
       `11011000110110001101111110111100`

## 6. Final Round Result
- **R1**: Result of the XOR operation:
  - `R1 = 11011000110110001101111110111100`
- **L1**: Set equal to `R0` (all zeros):
  - `L1 = 0, 0, 0,...,0`

### Final Output of First Round
- **L1 R1**:  
  `00000000000000000000000000000000 11011000110110001101111110111100`

### 3.4. Output of the First Round of DES (All Ones)
What is the output of the first round of the DES algorithm when both the plaintext and the key are all ones?

## 1. Key Generation - PC-1
- **Key (k1)**: Applying PC-1 results in 48 one bits:
  - `k1 = 1, 1, 1,...,1`

## 2. Initial Permutation (IP)
- **Plaintext (x)**: All bits set to one `(x = 1, 1, 1,...,1)`.
- After applying the initial permutation `IP(x)`, the result remains 64 one bits:
  - `L0 = 1, 1, 1,...,1` (32 bits)
  - `R0 = 1, 1, 1,...,1` (32 bits)

## 3. Function f (First Round)
1. **Expansion Permutation**:
   - Expands `R0` (all ones) into 48 one bits:
     - `y = 1, 1, 1,...,1`
   
2. **XOR Operation**:
   - Performs XOR between `k1` (all ones) and `y` (all ones), resulting in an array of all zeros:
     - `z = 0, 0, 0,...,0`

3. **S-Box Application**:
   - Divides `z` into 8 blocks of 6 bits (all zeros) and applies the S-boxes:
     - **Result** after S-boxes:  
       `11001111101001110010110001001101`

4. **Permutation**:
   - Applies a permutation on the result from the S-boxes:
     - **Result** after permutation:  
       `11011000110110001101101110111100`

5. **XOR with L0**:
   - Performs XOR between the permuted result and `L0` (all ones):
     - **Result**:  
       `00100111001001110010010001000011`

## 4. Final Round Result
- **R1**: Result of the XOR operation:
  - `R1 = 00100111001001110010010001000011`
- **L1**: Set equal to `R0` (all ones):
  - `L1 = 1, 1, 1,...,1`

### Final Output of First Round
- **L1 R1**:  
  `11111111111111111111111111111111 00100111001001110010010001000011`

  

# Question 3.5 - Avalanche Effect in DES

It is desirable for good block ciphers that a change in one input bit affects many output bits, a property called diffusion or the avalanche effect. In this section, we explore the avalanche effect in DES by applying an input word that has a "1" at bit position 57, with all other bits and the key set to zero. (Note: the input word must go through the initial permutation).

## a. How many S-boxes receive different inputs compared to the case when an all-zero plaintext is provided?

In the first round, only one S-box receives a different input because the initial permutation (IP) sends the "1" to position 33, affecting S1. This is demonstrated by a series of XOR operations between the key and the expanded right halves of the data blocks in each round, resulting in different inputs for the S-boxes.

### The XOR operations for each round are as follows:
```
-K1 ⊕ E(R0) = 000000 000000 000000 000000 000000 000000 000000 000000 

K1 ⊕ E(R0) = 010000 000000 000000 000000 000000 000000 000000 000001 
```

```
-K2 ⊕ E(R1) = 011011 110001 011011 110001 011011 110111 110111 111001 

K2 ⊕ E(R1) = 011010 100000 001011 110000 001011 110111 110011 111101
 ```
```
-K3 ⊕ E(R2) = 111100 001110 100111 110101 011101 011010 101001 011111 

K3 ⊕ E(R2) = 000100 000101 011110 101110 100110 100001 011101 010100 
```
```
-K4 ⊕ E(R3) = 101110 100011 111011 110101 011000 000100 001000 001010

K4 ⊕ E(R3) = 001011 110111 111111 110100 001101 010111 110100 001100 
```
```
-K5 ⊕ E(R4) = 110011 111010 101001 010000 000101 011101 011001 010011 

K5 ⊕ E(R4) = 101011 111100 001000 001011 111100 000100 001010 101110
```
```
-K6 ⊕ E(R5) = 110110 100010 101111 110111 110101 011001 011100 000111 

K6 ⊕ E(R5) = 010001 010110 100011 110010 101111 110111 111100 000001
```
```
-K7 ⊕ E(R6) = 101010 100010 100010 100011 110101 010001 010011 111110 

K7 ⊕ E(R6) = 011111 111011 111101 010011 110001 010010 101001 010101 
```
```
-K8 ⊕ E(R7) = 101111 110110 100010 100100 000111 110101 010111 111110 

K8 ⊕ E(R7) = 000011 110011 111011 111110 100001 010110 101011 111000 
```
```
-K9 ⊕ E(R8) = 010010 100000 001111 110100 000010 100111 111110 100001

K9 ⊕ E(R8) = 010011 110000 000000 001000 000001 010101 011001 010001 
```
```
-K10 ⊕ E(R9) = 010001 010000 000011 110010 100001 011000 001010 100001 

K10 ⊕ E(R9) = 101100 000100 000010 101101 011011 111010 100000 000110 
```
```
-K11 ⊕ E(R10) = 000100 001011 111010 100010 101010 100010 101111 111000 

K11 ⊕ E(R10) = 000101 010110 100001 011000 000111 110001 010100 000000 
```
```
-K12 ⊕ E(R11) = 011110 100111 111101 011111 110010 100010 101111 111101 

K12 ⊕ E(R11) = 011111 111010 101111 110100 000110 101110 101110 100001 
```
```
-K13 ⊕ E(R12) = 111001 011111 111111 111110 101011 111001 010100 001011 

K13 ⊕ E(R12) = 010010 101101 011100 000111 110010 101110 100010 100101 
```
```
-K14 ⊕ E(R13) = 001011 110100 001011 111011 110100 000110 101001 010100 

K14 ⊕ E(R13) = 111111 111101 011011 111010 101101 011001 011101 010011 
```
```
-K15 ⊕ E(R14) = 000000 001011 110001 011001 010101 011010 100001 010100 

K15 ⊕ E(R14) = 010001 010110 100110 101111 111010 101010 100010 100101 
```
```
-K16 ⊕ E(R15) = 111000 000100 001000 001110 100101 011110 100011 110011 

K16 ⊕ E(R15) = 010111 110111 111101 010100 000001 011011 111000 000101 
```
-Finally, we have 8*14+7+2=121 out of 128 S-boxes get different input 
## b. What is the minimum number of output bits from the S-boxes that will change according to the S-box design criteria?

In S-box 1 (S1), the minimum number of output bit changes, in response to a change in the input, can be as low as zero. For example, when analyzing the S1 box, the output for both `000001` and `011100` input values is `00` in binary. Thus, the output remains consistent even though the inputs differ by 4 bits.

## c. What is the output after the first round?  
### Case 1: Plaintext with all zeros

- **L0:** A 32-bit block of all zeros: ```0000 0000 0000 0000 0000 0000 0000 0000```
- **R0:** A 32-bit block of all zeros: ```0000 0000 0000 0000 0000 0000 0000 0000```
- **K1:** A 48-bit key with all bits set to zero:```000000 000000 000000 000000 000000 000000```
- **E(R0):** A 48-bit expansion of R0 (all zeros): ```000000 000000 000000 000000 000000 000000 000000 000000```
- **K1 ⊕ E(R0):** XOR of K1 and E(R0) results in: ```000000 000000 000000 000000 000000 000000 000000 000000```
- **S(K1 ⊕ E(R0)):** After passing through the S-boxes, the result is:```1110 1111 1010 0111 0010 1100 0100 1101```
- **f:** Applying the permutation P gives: ```1101 1000 1101 1000 1101 1011 1011 1100```
- **L1 = R0:** Remains unchanged: ```0000 0000 0000 0000 0000 0000 0000 0000```
- **R1 = L0 ⊕ f(R0, K1):** XOR of L0 and the result of f(R0, K1): ```1101 1000 1101 1000 1101 1011 1011 1100```
  
### Thus, the output after the first round is a combination of the above results:

-L1 = 0000 0000 0000 0000 0000 0000 0000 0000 R1 = ```1101 1000 1101 1000 1101 1011 1011 1100```


## d.  How many output bit after the first round have actually changed compared to the 
case when the plaintext is all zero? (Observe that we only consider a single round 
here. There will be more and more output differences after every new round. Hence 
the term avalanche effect.) 

-  Six different output bits comparing the previous question.


### 3.6. Avalanche Effect in DES Key

 - a. Assume an encryption with a given key. If the key bit at position 1 (prior to PC−1) is flipped, which S-boxes in which rounds are affected by the bit flip during DES encryption?

When a key bit at position 1 (before the PC-1 permutation) is flipped during DES encryption, its effect on the S-boxes across different rounds is as follows:

- 1. **Round 1:** The flipped key bit at position 1 influences S-boxes 2, 3, 4, 5, 6, and 7.
- 2. **Round 2:** The flipped key bit affects S-boxes 2, 3, 5, and 7.
- 3. **Round 3:** The flipped key bit impacts S-boxes 2, 3, 4, 6, and 7.
- 4. **Rounds 4-8:** The effect of the flipped key bit is observed on S-boxes 2, 3, 5, and 7.
- 5. **Rounds 9-16:** The key bit flip affects S-boxes 2, 3, 4, 6, and 7.

As seen, the impact of the key bit flip at position 1 varies across different rounds in the DES encryption process.


- b. Which S-boxes in which DES rounds are affected by this bit flip during DES decryption?

When a bit flip occurs in the key at position 1 during DES decryption, the impact on the S-boxes is similar to that during encryption, but in reverse order. This is due to the fact that DES decryption utilizes the subkeys in the reverse order compared to encryption. Consequently, the S-boxes affected by the key bit flip during decryption are the same as those affected during encryption, but the sequence of affected S-boxes is reversed.

## Advanced Encryption Standard (AES)

### 4.1. Output of the First Round of AES
For AES with a 128-bit block length and 128-bit key length, what is the output of the first round if the plaintext and the first subkey both consist of 128 ones? You can write your final results in a rectangular array format if you wish.

- First Step
In this step, each byte of the state is substituted using the AES S-Box. Given that the plaintext consists of 0xFF for each byte, the S-Box maps 0xFF to itself.
Therefore: 

- **State after Byte Substitution:** ```[FF FF FF FF] [FF FF FF FF] [FF FF FF FF] [FF FF FF FF]```

### Step 2: ShiftRows

The ShiftRows operation rearranges the bytes within each row of the state matrix. Since all bytes are the same (0xFF), this step does not alter the state:

- **State after ShiftRows:** ```[FF FF FF FF] [FF FF FF FF] [FF FF FF FF] [FF FF FF FF]```

### Step 3: MixColumns

In MixColumns, each column of the state matrix is transformed using matrix multiplication. For a column of all 0xFF, the transformation is as follows:

- **Matrix Multiplication for Each Column:** ```[02 03 01 01] [FF] = [E9] [01 02 03 01] [FF] = [E9] [01 01 02 03] [FF] = [E9] [03 01 01 02] [FF] = [E9]```
- In GF(2^8), `01 + 01 + 02 + 03 = 01`. Thus, the result for each column is: ```[E9] [E9] [E9] [E9]```
- **State after MixColumns:** ```[E9 E9 E9 E9] [E9 E9 E9 E9] [E9 E9 E9 E9] [E9 E9 E9 E9]``` 
### Step 4: Add Round Key

Perform a bitwise XOR between the state matrix and the round key. Given the round key is also 0xFF:

- **Compute the XOR:**```[E9 E9 E9 E9] ⊕ [FF FF FF FF] = [16 16 16 16] [E9 E9 E9 E9] ⊕ [FF FF FF FF] = [16 16 16 16] [E9 E9 E9 E9] ⊕ [FF FF FF FF] = [16 16 16 16] [E9 E9 E9 E9] ⊕ [FF FF FF FF] = [16 16 16 16]```
- **State after Add Round Key:** ```[16 16 16 16] [16 16 16 16] [16 16 16 16] [16 16 16 16]```
### Diffusion Check

For a diffusion check after one round of AES, let \( W = (w0, w1, w2, w3) = (0x01000000, 0x00000000, 0x00000000, 0x00000000) \) be the input in 32-bit chunks. The subkeys for the first round are:

- \( W0 = 0x2B7E1516 \)
- \( W1 = 0x28AED2A6 \)
- \( W2 = 0xABF71588 \)
- \( W3 = 0x09CF4F3C \)
- \( W4 = 0xA0FAFE17 \)
- \( W5 = 0x88542CB1 \)
- \( W6 = 0x23A33939 \)
- \( W7 = 0x2A6C7605 \)




### 4.2. Diffusion Properties of AES
- a. Compute the output of the first round of AES with input `W = (w0, w1, w2, w3) = (0x01000000, 0x00000000, 0x00000000, 0x00000000)` and subkeys `W0 = 0x2B7E1516`, `W1 = 0x28AED2A6`, `W2 = 0xABF71588`, `W3 = 0x09CF4F3C`, `W4 = 0xA0FAFE17`, `W5 = 0x88542CB1`, `W6 = 0x23A33939`, `W7 = 0x2A6C7605`. Indicate all intermediate steps for ShiftRows, SubBytes, and MixColumns.

### We have to represent the different outputs like a table:
![image](https://github.com/user-attachments/assets/a671c533-6a57-4b1f-adc4-d946066a9325)

Then, we have tu substite the different expressions with te S1 table, and we obtain:

![image](https://github.com/user-attachments/assets/741d9e9e-8367-44e2-83ac-f967d05a539c)

Then we apply the shift of the AES algorithm:

![image](https://github.com/user-attachments/assets/bbcf2b7a-20d9-44f1-8088-d004c3d3bfb8)


The final transformation (other than the k1 addition) is the MixColumn layer. This involves a Galois Extension Field matrix multiplication with the following description:
![image](https://github.com/user-attachments/assets/5ab93eec-d93b-4b0a-857c-0f98cdcb22a1)


The C values refer to the outputted column. The B values refer to the input columns which were the output of the ShiftRows layer. The indexes here are preserved from prior to the shift. Each new column can be calculated left-to-right using this procedure.

As such the calculation to be performed is as follows for each of the columns:

![image](https://github.com/user-attachments/assets/6c428d33-35a6-454f-aa80-b329786a6502)

This produces:

![image](https://github.com/user-attachments/assets/8d38ad3a-9190-4922-93f0-fc2401e20ffa)

After that, we apply the KeyAddition Layer for k1. And we obtain: ```F4CC6B539B60AA8F1F010F045790A2D3```

- b. Compute the output of the first round of AES for the case where all input bits are zero.
For the case that the input is all-zeroes, the state after the k0 key addition will be:

![image](https://github.com/user-attachments/assets/5c2e49f7-ed53-4867-a400-ff8ce2b36e8b)

After appliying the byteSubstitution and ShiftRows layer, we obtain:

![image](https://github.com/user-attachments/assets/2c7bbc4d-f0e6-4693-af4f-515e3d2a2841)

After that, we introduce some difussion. We obtain: ```DCD87F6F9B60AA8F1F010F045790A2D3```

- c. How many output bits have changed? Note that we only consider a single round — further rounds will cause more output bits to change (avalanche effect).
- 
We can see how many output bits have been altered by XORing the two output values together. This produces:

```2814143c000000000000000000000000```

In this form, we can clearly see that only the first column is altered after the first round.

```2814143c16=101000000101000001010000111100```










