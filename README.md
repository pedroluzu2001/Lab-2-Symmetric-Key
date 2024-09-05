# Lab-2-Symmetric-Key
Objective: The key objective of this lab is to understand the range of symmetric key methods 
used within symmetric key encryption. We will introduce block ciphers, stream ciphers and 
padding. The key tools used include OpenSSL, Python and JavaScript. 

# OpenSSL (0.25p)

OpenSSL is a standard tool that we used in encryption. It supports many of the standard symmetric key methods, including AES, 3DES, ChaCha20, and RC4.

## No Description Result

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

**Why has it changed?**Cause the behavior of base64 codification, what has changed two times. 

### A.6 Now let’s decrypt the encrypted file with the correct format:

- `openssl enc -d -aes-256-cbc -in encrypted.bin -pass pass:napier base64`

**Has the output been decrypted correctly?**

**What happens when you use the wrong password?**

### A.7 Now encrypt a file with Blowfish and see if you can decrypt it.

**Did you manage to decrypt the file? [Yes][No]**

# Padding (AES) (0.25p)

With encryption, we normally use a block cipher, and where we must pad the end blocks to make sure that the data fits into a whole number of blocks. Some background material is here:

- Web link (Padding): [http://asecuritysite.com/encryption/padding](http://asecuritysite.com/encryption/padding)

## No Description Result

### B.1 With AES which uses a 256-bit key, what is the normal block size (in bytes).

**Block size (bytes):**

**Number of hex characters for block size:**

### B.2 Go to:

- Web link (AES Padding): [http://asecuritysite.com/symmetric/padding](http://asecuritysite.com/symmetric/padding)

Using 256-bit AES encryption, and a message of “kettle” and a password of “oxtail”, determine the cipher using the differing padding methods (you only need to show the first six hex characters).

**CMS:**

### B.3 For the following words, estimate how many hex characters will be used for the 256-bit AES encryption (do not include the inverted commas for the string to encrypt):

**Number of hex characters:**

- “fox”:
- “foxtrot”:
- “foxtrotanteater”:
- “foxtrotanteatercastle”:

# Padding (DES) (0.25p)

In the first part of this lab we will investigate padding blocks:

## No Description Result

### C.1 With DES which uses a 64-bit key, what is the normal block size (in bytes):

**Block size (bytes):**

**Number of hex characters for block size:**

### C.2 Go to:

- Web link (DES Padding): [http://asecuritysite.com/symmetric/padding_des](http://asecuritysite.com/symmetric/padding_des)

Using 64-bit DES key encryption, and a message of “kettle” and a password of “oxtail”, determine the cipher using the differing padding methods.

**CMS:**

### C.3 For the following words, estimate how many hex characters will be used for the 64-bit key DES encryption:

**Number of hex characters:**

- “fox”:
- “foxtrot”:
- “foxtrotanteater”:
- “foxtrotanteatercastle”:

# Python Coding (Encrypting) (1p)

In this part of the lab, we will investigate the usage of Python code to perform different padding methods and using AES. Install the necessary cryptographic libraries for AES-256 encryption. In the following we will use a 128-bit block size, and will pad the plaintext to this size with CMS, and then encryption with AES ECB. We then decrypt with the same key, and then unpad:

Run the program, and prove that it works. And identify the code which does the following:

**Generates key:**

**Pads and unpads:**

**Encrypts and decrypts:**

### D1. Now update the code so that you can enter a string and the program will show the cipher text. The format will be something like:

- `python d_01.py hello mykey`

where “hello” is the plain text, and “mykey” is the key.

Now determine the cipher text for the following (the first example has already been completed – just add the first four hex characters):

| Message   | Key        | CMS       | Cipher              |
|-----------|------------|-----------|---------------------|
| “hello”   | “hello123” |           | 0a7e (c77951291795bac6690c9e7f4c0d) |
| “inkwell” | “orange”   |           |                     |
| “security”| “qwerty”   |           |                     |
| “Africa”  | “changeme” |           |                     |

### D2. Now copy your code and modify it so that it implements 64-bit DES and complete the table (Ref to: [https://asecuritysite.com/symmetric/padding_des2](https://asecuritysite.com/symmetric/padding_des2)):

| Message   | Key        | CMS       | Cipher              |
|-----------|------------|-----------|---------------------|
| “hello”   | “hello123” |           | 4cd9 (24baf0c9ac60) |
| “inkwell” | “orange”   |           |                     |
| “security”| “qwerty”   |           |                     |
| “Africa”  | “changeme” |           |                     |

Now modify the code so that the user can enter the values from the keyboard, such as with:

- `cipher=input('Enter cipher:')`
- `password=input('Enter password:')`

# Python Coding (Decrypting) (1p)

Now modify your coding for 256-bit AES ECB encryption, so that you can enter the cipher text, and an encryption key, and the code will decrypt to provide the result. You should use CMS for padding. With this, determine the plaintext for the following (note, all the plain text values are countries around the World):

| CMS Cipher (256-bit AES ECB) | Key     | Plain text |
|-------------------------------|---------|------------|
| b436bd84d16db330359edebf49725c62 | “hello” |            |
| 4bb2eb68fccd6187ef8738c40de12a6b | “ankle” |            |
| 029c4dd71cdae632ec33e2be7674cc14 | “changeme” |            |
| d8f11e13d25771e83898efdbad0e522c | “123456” |            |

Now modify your coding for 64-bit DES ECB encryption, so that you can enter the cipher text, and an encryption key, and the code will decrypt to provide the result. You should use CMS for padding. With this, determine the plaintext for the following (note, all the plain text values are countries around the World):

| CMS Cipher (128-bit DES ECB) | Key     | Plain text |
|------------------------------|---------|------------|
| 0b8bd1e345e7bbf0 | “hello” |            |
| 6ee95415aca2b33c | “ankle” |            |
| c08c3078bc88a6c3 | “changeme” |            |
| 9d69919c37c375645451d92ae15ea399 | “123456” |            |

Now update your program, so that it takes a cipher string in Base-64 and converts it to a hex string and then decrypts it. From this now decrypt the following Base-64 encoded cipher streams (which should give countries of the World):

| CMS Cipher (256-bit AES ECB) | Key     | Plain text |
|------------------------------|---------|------------|
| /vA6BD+ZXu8j6KrTHi1Y+w==    | “hello” |            |
| nitTRpxMhGlaRkuyXWYxtA==    | “ankle” |            |
| irwjGCAu+mmdNeu6Hq6ciw==    | “changeme” |            |
| 5I71KpfT6RdM/xhUJ5IKCQ==    | “123456” |            |

# Stream Ciphers (1p)

## ChaCha20 and RC4

### F.1 ChaCha20

Now create a Python code for ChaCha20. Determine the cipher text for the following (the strings should be fruit names):

| Cipher | Key       | Plain text |
|--------|-----------|------------|
| e47a2bfe646a  | “qwerty”  |            |
| ea783afc66    | “qwerty”  |            |
| e96924f16d6e  | “qwerty”  |            |

### F.2 RC4

Now create a Python code for RC4. Determine the cipher text for the following (the strings should be fruit names):

| Cipher       | Key       | Plain text |
|--------------|-----------|------------|
| 8d1cc8bdf6da | “napier”  |            |
| 911adbb2e6dda57cdaad | “napier”  |            |
| 8907deba     | “napier”  |            |

### F.3 OTP and Exhaustive Search

Finally explain why an exhaustive search cannot work with OTP (One-Time Pad), even though it is unconditionally secure. 

# Data Encryption Standard (DES) (0.25p)

### 3.1 S-boxes in DES

Verify that the S-boxes are non-linear for the given input pairs.

### 3.2 Initial and Inverse Permutation

Show that IP−1(IP(x)) = x for the first five bits of x.

### 3.3 First Round Encryption Output

Explain what the first round encryption output should be for the given input bits.

