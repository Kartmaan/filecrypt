# Filecrypt
This Python script intended to be executed on the command line, allows to **encrypt and decrypt files present in the current folder of the script**. The program is based on the `cryptography` module and in particular its Fernet class allowing symmetric encryption using the 128-bit AES algorithm.

## `encrypt` command
Encrypts a file found in the script's **current folder**. By default, the program generates a `filekey.key` file in the current folder containing the randomly generated secret key from which the file will be decrypted. Since this is a symmetrical cryptographic algorithm **This file is to be kept preciously** in order to be able to decrypt the file later and prevent the file from being read by others.

By default, the command must take two arguments:
- The name of the file to encrypt (*with its extension*)
- The choice of procedure: 
  - `-ow` / `--overwrite` : the file will be overwritten by its encrypted version (in the case of an image file for example, it will therefore become unusable).(corrupted) in its encrypted form
  - `-c` / `--copy` : The plaintext file will be copied before being overwritten by its encrypted version.

### `--filekey` option
If the user already has a filekey with which to encrypt the file, the `--filekey`/`-k` option lets you enter the name of the desired filekey. In this case, no filekey file will be generated during the encryption operation.

### Examples
Let's suppose we want to encrypt a file named psw.txt :

**Overwrite option** :

`python filecrypt.py encrypt psw.txt -ow`

**Copy option** :

`python filecrypt.py encrypt psw.txt -c`

> **Note**: If the `--filekey` option isn't enabled, the encryption operation will leave a `filekey.key` file in the current folder which must be kept safe, as it contains the secret key for decrypting the file.

**Filekey option**

File Encryption using a filekey already present in the current folder :

`python filecrypt.py encrypt --filekey filekey.key psw.txt -c`

## `decrypt` command
Decrypts a file found in the current folder using a key file also present in the folder and in which the secret key is located. The function must take 2 parameters :
- The name of the file to decrypt (*with its extension*)
- The name of the key file present in the current folder (*with its extension*)

### Example
Case examples for psw.txt file decryption :

`python filecrypt.py decrypt psw.txt filekey.key`

## `install` command
Installs the `cryptography` module and its dependencies via the pip command

### Example
`python filecrypt.py install`

All necessary dependencies will be installed via pip

## `read` command
Displays the Base64 code present in a filekey

### Example
`python filecrypt.py read filekey.key`

Display example:

`MWpYeBrqiaVVZIOZrJFntiF2K0_ZYZZ2eCxBQ1_CuAI=`


## Some technical details
### What's Fernet ?
Fernet (from `cryptography` module) is an implementation of the AES algorithm using a 128-bit key. Fernet offers an abstraction that allows developers to encrypt and decrypt data without having to worry about the complexities of implementing AES and other security mechanisms.

### What level of security?
* **AES** : Data is encrypted using AES (**A**dvanced **E**ncryption **S**tandard), a symmetrical encryption algorithm that encrypts data in blocks of a fixed size.


* **128-bits** : This is the size of the secret key. It offers a high level of security, making brute-force attacks extremely difficult ($2^{128}$ possible combinations).


* **CBC mode** : The **C**ipher **B**lock **C**haining links the encryption of each block to the previous one. Each block of plaintext data is XOR'd with the preceding encrypted block before being encrypted. So if a bit is modified in the ciphertext, this will affect not only the decryption of this block, but also of all subsequent blocks.


* **Initialisation Vector (IV)** : Since the first block has no precedent, it's subjected to a random initialization vector: a series of randomly generated bits of the same size as the block, which acts as the “previous block”. This randomness masks repetitions in the code, even if the plain text begins with the same data in several sessions.


* **Crypto secure RNG** : The secret key and the initialisation vector are randomly generated using `os.urandom()`, which relies on the operating system's entropy (*harware interupts, network data, running processes...*) to make generation as unpredictable as possible (CSPRNG).


* **Padding PKCS7** : This technique ensures that the data to be encrypted always occupies an integer number of blocks, as required by the AES algorithm. To do this, the function adds padding bytes to the end of the plaintext data if it isn't a multiple of the desired block size.


* **HMAC** : **H**ash-based **M**essage **A**uthentication **C**ode is a cryptographic function used to verify the integrity and authenticity of a message, it's calculated on the basis of the encrypted data. **If the integrity of the encrypted file is compromised, it becomes impossible to decrypt it**.


* **SHA-256** : A cryptographic hash function that produces a 256-bit hash value. It's used to generate the **M**essage **A**uthentication **C**ode.