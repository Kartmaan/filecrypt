# Filecrypt
This Python script intended to be executed on the command line, allows to **encrypt and decrypt files present in the current folder of the script**. The program is based on the `cryptography` module and in particular its Fernet class allowing symmetric encryption using the 128-bit AES algorithm.

## `encrypt` funtion
Encrypts a file found in the script's **current folder**. Before encrypting the file, the program generates a `filekey.key` file containing the randomly generated secret key from which the file will be encrypted. Since this is a symmetrical cryptographic algorithm **This file is to be kept preciously** in order to be able to decrypt the file later and prevent the file from being read by others.

The function must take two arguments:
- The name of the file to encrypt (*with its extension*)
- The choice of procedure: 
  - `ow` : the file will be overwritten, in the case of an image file for example, it will therefore become unusable (corrupted) in its encrypted form
  - `c` : the file will be copied to the current folder before being overwritten

Case examples for psw.txt file encryption :

**Overwrite mode** :

`python filecrypt.py encrypt psw.txt ow`

**Copy mode** :

`python filecrypt.py encrypt psw.txt c`

The encryption operation will leave a `filekey.key` file in the current folder which must be kept safe.

## `decrypt` function
Used to decrypt a file found in the current folder using a key file also present in the folder and in which the secret key is located. The function must take 2 parameters :
- The name of the file to decrypt (*with its extension*)
- The name of the key file present in the current folder (*with its extension*)

Case examples for psw.txt file decryption :

`python filecrypt.py decrypt psw.txt filekey.key`

## Some technical details
### What's Fernet ?
Fernet (from `cryptography` module) is an implementation of the AES algorithm using a 128-bit key. Fernet offers an abstraction that allows developers to encrypt and decrypt data without having to worry about the complexities of implementing AES and other security mechanisms.

### What level of security?
* **AES** : Data is encrypted using AES (**A**dvanced **E**ncryption **S**tandard), a symmetrical encryption algorithm that encrypts data in blocks of a fixed size.
* **CBC mode** : The Cipher Block Chaining links the encryption of each block to the previous one. This makes the encrypted data more resistant to certain attacks (*If a bit is modified in the ciphertext, this will affect not only the decryption of this block, but also of all subsequent blocks*).
* **128-bits** : A 128-bit key offering a high level of security, making brute-force attacks extremely difficult
* **Crypto secure RNG** : The secret key is randomly generated using `os.urandom()`, which relies on the operating system's entropy (*harware interupts, network data, running processes...*) to make generation as unpredictable as possible (CSPRNG).
* **Padding PKCS7** : This technique ensures that the data to be encrypted always occupies an integer number of blocks, as required by the AES algorithm.
* **HMAC** : **H**ash-based **M**essage **A**uthentication **C**ode is a cryptographic function used to verify the integrity and authenticity of a message. **If the integrity of the encrypted file is compromised, it becomes impossible to decrypt it**.
* **SHA-256** : A cryptographic hash function that produces a 256-bit hash value. It is used to generate the MAC.