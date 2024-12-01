- [Filecrypt](#filecrypt)
  - ['encrypt' command](#encrypt-command)
    - [overwrite option](#overwrite-option)
    - [Examples](#examples)
      - [**Method 1** : By generating a random filekey in the current folder](#method-1--by-generating-a-random-filekey-in-the-current-folder)
      - [**Method 2** : By using a filekey already present in the current folder](#method-2--by-using-a-filekey-already-present-in-the-current-folder)
      - [**Method 3** : By using a password and optionally a salt value](#method-3--by-using-a-password-and-optionally-a-salt-value)
  - ['decrypt' command](#decrypt-command)
    - [Examples](#examples-1)
      - [**Method 1** : By using a filekey present in the current folder](#method-1--by-using-a-filekey-present-in-the-current-folder)
      - [**Method 2** : By using a password and a salt](#method-2--by-using-a-password-and-a-salt)
  - ['install' command](#install-command)
    - [Example](#example)
  - ['read' command](#read-command)
    - [Example](#example-1)
  - ['create' command](#create-command)
    - [Example](#example-2)
  - ['timestamp' command](#timestamp-command)
    - [Example](#example-3)
      - [Method 1 : By using a file encrypted with a filekey](#method-1--by-using-a-file-encrypted-with-a-filekey)
      - [Method 2 : By using a file encrypted with a password and a salt](#method-2--by-using-a-file-encrypted-with-a-password-and-a-salt)
  - [Some technical details](#some-technical-details)
    - [What's Fernet ?](#whats-fernet-)
    - [What level of security?](#what-level-of-security)
    - [Key and token](#key-and-token)
      - [Key](#key)
      - [Token](#token)

# Filecrypt
This Python script allows to **encrypt and decrypt files present in the current folder of the script**. The program is based on the `cryptography` module and in particular its Fernet class allowing symmetric encryption using the 128-bit AES algorithm.

## 'encrypt' command
Encrypts a file present in the current folder using three different methods :
1. By generating a random filekey in the current folder
2. By using a valid filekey already present in the current folder
3. By using a password and optionally a salt value

These three methods are mutually exclusive, but **must** include the name of the file to be encrypted and the `overwrite` option.

### overwrite option
- `-ow` / `--overwrite` : the file will be overwritten by its encrypted version (*in the case of an image file for example, it will therefore become corrupted*)
- `-c` / `--copy` : The plaintext file will be copied before being overwritten by its encrypted version.

### Examples
#### **Method 1** : By generating a random filekey in the current folder
Let's suppose we want to encrypt a file named `psw.txt` by overwriting it :

`python filecrypt.py encrypt psw.txt -ow`

Same thing, but first copy the file to the current folder before encrypting it.

`python filecrypt.py encrypt psw.txt -c`

A filekey named `filekey.key` will be created in the current folder.

> **Note**: The filekey **doesn't contain the ciphertext but only the secret key**. It should be kept in a safe place.

#### **Method 2** : By using a filekey already present in the current folder
The `-f`/`--filekey` option lets us specify the filekey to be used

`python filecrypt.py encrypt psw.txt -f filekey.key -ow`

#### **Method 3** : By using a password and optionally a salt value

Fernet can also generate keys from : 
- a password : `-p` / `--password`
- and a salt value : `-s` / `--salt`

When no salt value is entered, the script will automatically generate one in the form of 16 random bytes (generated by `os.urandom()`). This value will be encoded in base64 urlsafe so that it can be easily displayed to the user and kept in a safe place.

> **Caution**: With identical passwords, two encrypted files cannot be decrypted if they have different salt values. That's why it's crutial to keep both the password AND the salt in a safe place. If the file is encrypted again without specifying a salt value, a new one will be randomly generated, making the old one obsolete. 

Let's say we have an image named `image.jpg` in the current folder and we want to encrypt it with the password: `notastrongpsw` (*a password whose only virtue is honesty*): 

`python filecrypt.py encrypt image.jpg -p notastrongpsw -ow`

Since no salt has been entered, the value will be generated automatically. The file has been encrypted inplace and the random generated salt is displayed on the terminal :

```
- - - - SALT (KEEP IT SAFE) - - - - -
zhWYYqNubPOb0aH_AAGV3Q==
- - - - - - - - - - - - - - - - - - -
```
When the time comes to decrypt the file, the password AND this salt will be required.

Now let's say we want to encrypt the same file, but this time with a salt we already own. 

`python filecrypt.py encrypt image.jpg -p notastrongpsw -s zhWYYqNubPOb0aH_AAGV3Q== -ow`

> **Note** : It is recommended to use salt values generated directly from the script to ensure compliance with standardization.

## 'decrypt' command
Decrypts a file present in the current folder using two different methods :
1. By using a filekey present in the current folder
2. By using a known password and a salt

### Examples
#### **Method 1** : By using a filekey present in the current folder

Decryption of a file named `psw.txt` using a filkey named `filekey.key` present in the current folder :

`python filecrypt.py decrypt psw.txt filekey.key`

#### **Method 2** : By using a password and a salt
This method is used to decrypt a file that has been encrypted using a password and a salt value known to the user.

Here we decrypt the file `image.jpg`, encrypted in our example in the 'encrypt command' section with the password `notastrongpsw` and the salt `zhWYYqNubPOb0aH_AAGV3Q==` :

`python filecrypt.py decrypt image.jpg -p notastrongpsw -s zhWYYqNubPOb0aH_AAGV3Q==`

> **Note**: Unlike the `encrypt` command, where the `--salt` option was optional for encrypting with a password, here, the `--password` AND `--salt` options must both be set.

## 'install' command
Installs the `cryptography` module and its dependencies via the pip command

### Example
`python filecrypt.py install`

All necessary dependencies will be installed via pip

## 'read' command
Displays the Base64 code present in a filekey

### Example
`python filecrypt.py read filekey.key`

Display example:

`MWpYeBrqiaVVZIOZrJFntiF2K0_ZYZZ2eCxBQ1_CuAI=`

## 'create' command
Creates a filekey in the current folder by providing the desired name and the key (*base64 urlsafe*). 

**Practical example**: after encrypting a file, for security reasons we don't want to keep the filekey on the computer, so we can extract its key using the `read` command, copy/paste it somewhere else (or even copy it onto paper) and delete the filekey. When we want to decrypt this file, the filekey can be recreated using the `create` command.

### Example
Create a file named secretkey with its key :

`python filecrypt.py create secretkey ejK4-SDwj4CFuQ28L28KMjaNVgg-BH1l6FIF3dLsgfk=`

The command creates a filekey in the current folder, named secret.key, with the supplied key.

## 'timestamp' command
This command extracts the timestamp of a Fernet token (*from an encrypted file*), i.e. the timestamp at which the file was encrypted. To do this, the command needs the name of the encrypted file in the current folder as well as the filekey used to encrypt it or the password and salt.

### Example
Here are examples of the two different methods: 
1. By using a file encrypted with a filekey
2. By using a file encrypted with a password and a salt

Here, we want to extract the timestamp from an encrypted file named `image.jpg`

#### Method 1 : By using a file encrypted with a filekey
`python filecrypt.py timestamp image.jpg -f filekey.key`

#### Method 2 : By using a file encrypted with a password and a salt
`python filecrypt.py timestamp image.jpg -p notastrongpsw -s yAccWy42_ngl2wDMO528jg==`

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


* **HMAC** : **H**ash-based **M**essage **A**uthentication **C**ode is a cryptographic function used to verify the integrity and authenticity of a message (Token), it's calculated on the basis of the encrypted data. **If the integrity of the encrypted file is compromised, it becomes impossible to decrypt it**.


* **SHA-256** : A cryptographic hash function that produces a 256-bit hash value. It's used to generate the **M**essage **A**uthentication **C**ode.


* **Password & Salt** : Data can be encrypted using a user-memorable password, which is **derived** to be 128 bits long key. This password is also “mixed” with a sequence of random bits called “**salt**” before being hashed. In this way, knowing or guessing the password is not enough to decrypt the message, knowing the salt value is also necessary.
  ><p style="text-align: center;"><b>Key derivation</b></p> 
  >Key derivation is the principle of using a single secret key (<i>often called the master key, represented here by our password</i>) to generate several different keys of any desired length (<i>using an algorithm, PBKDF2 in our case</i>). To create these new keys, we generally use cryptographic hash functions. These functions take as input the master key (<i>our password</i>) and other information, such as the salt, to produce as output a unique and difficult-to-invert value, which will be our new key. This method has several advantages: <br><br>

  >- <b>Security</b> : By having several derived keys, we limit the risks if one key is compromised. If an attacker discovers one of the derived keys, he won't have access to the master key and therefore to the other keys.<br><br>

  >- <b>Flexibility</b> : We can generate specific keys for different operations, allowing to tailor our security system to our needs.<br><br>

  >- <b>Efficiency</b> : Instead of storing and managing several independent keys, we can store a single master key and generate the other keys as needed.<br><br>

  ><p style="text-align: center;"><b>Salt</b></p>
  >Imagine you want to preserve a dish with a unique taste. To make it inimitable, you can add a pinch of specific salt to your recipe. This salt, unique to your dish, will make it impossible for anyone else to reproduce exactly the same taste using the same basic ingredients. In cryptography, the “salt” plays a similar role. It's a random string of characters added to a password before it's hashed. This hash, i.e. the transformation of the password into a fixed-length string of characters, is used to store the password securely. Thus, even if the attacker recovers the master key (the password), it will be useless to him if it's not combined with the salt value.

### Key and token
The key and the token are two key concepts used by Fernet to encrypt and decrypt data.

#### Key
A 256-bit key (32 bytes), randomly generated and used to encrypt and decrypt data. The key is divided into two parts: an **encryption key** and a **signing key**, each 128 bits (16 bytes) long. This division is at the heart of Fernet's cryptographic mechanism, which combines encryption and authentication.

* **Key format** : A base64url key with the following fields:
  * **Signing-key, (128 bits)** : used to calculate cryptographic authentication (HMAC) on the token (*the encrypted data*). Indeed, token authentication is based not only on the ciphertext (*and other metadata*), but also on the signing-key. This ensures that the person decrypting the file actually owns the original key.

  * **Encryption-key, (128 bits)** : used by the AES algorithm in CBC (Cipher Block Chaining) mode to transform plaintext data into ciphertext data.
  
  So, if the encryption-key part is modified, decryption becomes impossible, and if the signing-key part is modified, the token's HMAC is no longer valid, and here again, decryption is impossible.

#### Token
A data container encapsulating everything needed to decrypt the data or verify its integrity.

* **Token format** : Coded in base64 urlsafe, it contains the following fields:

  * **Version, (8 bits)** : denotes which version of the format is being used by the token. Currently there is only one version defined, with the value 128 (0x80)

  * **Timestamp, (64 bits)** : a 64-bit unsigned big-endian integer. It records the number of seconds elapsed between January 1, 1970 UTC and the time the token was created

  * **Initialisation Vector (IV), (128 bits)** : the 128-bit Initialization Vector (see above) used in AES encryption and decryption of the Ciphertext. When generating new fernet tokens, the IV must be chosen uniquely for every token. With a high-quality source of entropy, random selection will do this with high probability.

  * **Ciphertext, variable length, (multiple of 128 bits)** : has variable size, but is always a multiple of 128 bits, the AES block size. It contains the original input message, padded and encrypted.

  * **HMAC, (256 bits)** : (**H**ash-based **M**essage **A**uthentication **C**ode) used to authenticate the token, i.e. the header (*version and timestamp*), the ciphertext and the IV. This authentication key is calculated using the signing-key as the secret key. Thus, HMAC ensures not only integrity, but also authenticity.