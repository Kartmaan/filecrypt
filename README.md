- [Filecrypt](#filecrypt)
  - [Compatibility](#compatibility)
  - [How to use it](#how-to-use-it)
- [Commands](#commands)
  - [`encrypt` : Encrypt a file](#encrypt--encrypt-a-file)
    - [**Method 1** : By generating a random filekey in the current folder](#method-1--by-generating-a-random-filekey-in-the-current-folder)
    - [**Method 2** : By using a filekey already present in the current folder](#method-2--by-using-a-filekey-already-present-in-the-current-folder)
    - [**Method 3** : By using a password](#method-3--by-using-a-password)
  - [`decrypt` : Decrypt a file](#decrypt--decrypt-a-file)
    - [**Method 1** : By using a filekey present in the current folder](#method-1--by-using-a-filekey-present-in-the-current-folder)
    - [**Method 2** : By using a password](#method-2--by-using-a-password)
  - [`install` : Install the required modules](#install--install-the-required-modules)
  - [`psw` : Generate a secure password](#psw--generate-a-secure-password)
  - [`read` : Display the key of a filekey](#read--display-the-key-of-a-filekey)
  - [`create` : Create a filekey](#create--create-a-filekey)
  - [`timestamp` : Displays the timestamp of an encrypted file](#timestamp--displays-the-timestamp-of-an-encrypted-file)
  - [`copykey` : Copy a filekey's Base64 key to the clipboard](#copykey--copy-a-filekeys-base64-key-to-the-clipboard)
  - [`getsalt` : Extract the salt from a password-encrypted file](#getsalt--extract-the-salt-from-a-password-encrypted-file)
  - [`verify` : Verify that a key/password can decrypt a file](#verify--verify-that-a-keypassword-can-decrypt-a-file)
  - [`clean` : Clear the clipboard](#clean--clear-the-clipboard)
  - [`delete` : Delete files/folders securely](#delete--delete-filesfolders-securely)
  - [`zip` : Zip files/folders](#zip--zip-filesfolders)
  - [`unzip` : Unzip files/folders](#unzip--unzip-filesfolders)
- [Some technical details](#some-technical-details)
  - [What's Fernet ?](#whats-fernet-)
  - [What level of security?](#what-level-of-security)
  - [Key and token](#key-and-token)
    - [Key](#key)
    - [Token](#token)
  - [Script SAFE\_MODE](#script-safe_mode)

# Filecrypt
<img width="380" height="380" alt="filecrypt_logo" src="https://github.com/user-attachments/assets/2a140939-496e-4f93-b14f-ec947575661a" />


This Python script encrypts/decrypts files located in the script's current folder. The program is based on **Fernet**, an implementation of the AES-128 algorithm.

> For security reasons, the script can only be placed in a non-sensitive area of the system, and can only access its current folder. If the script is placed in a sensitive area, SAFE_MODE is activated, preventing the call of any file-modifying function (see 'Some technical details' section for more information).

## Compatibility
The script has been tested on **Windows** and **Linux**. Python >= 3.10 required

## How to use it
To use this script, simply :
1. Place this script (*or a copy*) in the folder containing the files to be encrypted or decrypted.
2. Go to this folder from the terminal.
3. Call the script followed by the desired command. For example: 

    `C:\Users\Bob\Pictures> python filecrypt.py encrypt image.jpg -ow`

For a reminder of commands in the script: `python filecrypt.py --help` 

# Commands
## `encrypt` : Encrypt a file
Encrypts a file present in the current folder using three different methods :
1. By generating a random filekey in the current folder
2. By using a valid filekey already present in the current folder
3. By using a password (salt is generated and embedded automatically)

These three methods are mutually exclusive, but **must** include the name of the file to be encrypted and the `overwrite` option.

**Options**
- `-ow` / `--overwrite` : the file will be overwritten by its encrypted version (*in the case of an image file for example, it will therefore become corrupted*)
- `-c` / `--copy` : the plaintext file will be copied before being overwritten by its encrypted version.
- `-cs` / `--copysecret` : automatically copies the Base64 secret key contained in the generated filekey to the clipboard. In password mode, this option has no effect — the salt is embedded in the file and can be retrieved with the `getsalt` command.

> **Note**: The `-c` / `--copy` and `-ow` / `--overwrite` options are mutually exclusive but optional: if no option is added, the `--copy` option will be enabled by default for security reasons. This allows for a more concise syntax:
> 
> `python filecrypt.py encrypt psw.txt`
>
> In the following examples, we include these options to avoid any ambiguity.

### **Method 1** : By generating a random filekey in the current folder
Let's suppose we want to encrypt a file named `psw.txt` by overwriting it :

`python filecrypt.py encrypt psw.txt -ow`

Same thing, but first copy the file to the current folder before encrypting it.

`python filecrypt.py encrypt psw.txt -c`

A filekey named `filekey.key` will be created in the current folder.

> **Note 1**: For standardization reasons and to avoid unfortunate modifications to a .txt format, all generated filekeys are in .`key` format.

> **Note 2**: The filekey **doesn't contain the ciphertext but only the secret key**. It should be kept in a safe place.

### **Method 2** : By using a filekey already present in the current folder
The `-f`/`--filekey` option lets us specify the filekey to be used

`python filecrypt.py encrypt psw.txt -f filekey.key -ow`

### **Method 3** : By using a password

The `-p` / `--password` option encrypts the file using a password. A random 16-byte salt is generated automatically by the script and **embedded directly in the encrypted file** as a prefix. The user never needs to see, note, or re-enter the salt — it travels with the file and is recovered automatically at decryption time.

Let's say we have an image named `image.jpg` in the current folder and we want to encrypt it with a password:

`python filecrypt.py encrypt image.jpg -p -ow`

A confidential input field appears to receive the password:

`> Password: *************`

The file is encrypted in place. The salt is silently embedded in the output file and requires no further action from the user.

```
---- Encryption of image.jpg ----
Data encryption...
Encrypted data writing...
---- Operation completed successfully ----
The salt has been embedded in the encrypted file.
Use 'getsalt' to inspect it if needed.
```

> **Note**: Only the password needs to be kept safe. The salt is cryptographically public — its value alone, without the password, is useless to an attacker. It can be inspected at any time using the `getsalt` command.

## `decrypt` : Decrypt a file
Decrypts a file present in the current folder using two different methods :
1. By using a filekey present in the current folder
2. By using a password (salt is recovered automatically from the file)

### **Method 1** : By using a filekey present in the current folder

Decryption of a file named `psw.txt` using a filkey named `filekey.key` present in the current folder :

`python filecrypt.py decrypt psw.txt filekey.key`

> **Note** : For standardization reasons and to avoid unfortunate modifications to a .txt format, all filekeys must be in `.key`.

### **Method 2** : By using a password
This method is used to decrypt a file that was encrypted using a password. The salt is recovered automatically from the first 16 bytes of the encrypted file — the user only needs to provide the password.

Here we decrypt the file `image.jpg` encrypted with the `-p` option:

`python filecrypt.py decrypt image.jpg -p`

A confidential input field appears to receive the password:

`> Password: *************`

The salt is then recovered silently from the file and decryption proceeds:

```
---- Decryption of image.jpg ----
Salt recovered from file...
Decrypting data...
---- Operation completed successfully ----
```

## `install` : Install the required modules
Installs all non built-in modules and their dependencies via the pip command.

> Note: When the script is launched, if the import of a non built-in module encounters an ImportError, a request is made to the user to automatically install the missing modules.

**Example**

`python filecrypt.py install`

## `psw` : Generate a secure password
Generates a strong password and print it, so that it can be used to encrypt files. By default, the password is 17 characters long, made up of : 
- Upper letters
- Lower letters 
- Digits
- Symbols

**Options**:

- `-cs` / `--copysecret` : automatically copies the generated password to the clipboard.

> **Password entropy** 
> 
> In information theory, entropy measures the degree of uncertainty (*or randomness*) associated with a random variable. The higher the entropy, the more unpredictable the variable. Applied to passwords, entropy quantifies the difficulty for an attacker to guess the password. The password entropy value, expressed in bits, is defined by the following formula :
>  
> $E = L \cdot \log_{2}(R)$
> 
> Where L is the length of the password and R is the possible range of character types in the password (In other words, the number of possible states for each character).
>
> Typically, a strong or high-entropy password is at least 80 bits. Anything less than 50 bits is relatively easy for a machine to crack, for example, a password with a length of 6 and composed entirely of numbers has an entropy of 20, which is easily cracked by brute force. In our case we have 94 possible states for each character of the password :
> - 26 upper letters
> - 26 lower letters
> - 10 digits
> - 32 symbols
> 
> Applying the formula for a password length of 17, we have :
>
> $E = 17 \cdot \log_{2}(94) = 111.42$
>
> The passwords generated by the command will therefore have an entropy of slightly more than **111 bits**, which satisfies most safety recommendations.

**Example**
```
python filecrypt.py psw
> rv1rX\L!4m=v=[u0c
```

With copysecret option:
```
> python filecrypt.py psw -cs
-dwV2_3Cb'":DhJAI
Password copied to clipboard.
Don't forget to clean the clipboard after use ('clean' command).
```

## `read` : Display the key of a filekey
Displays the Base64 code present in a filekey

**Example**
```
python filecrypt.py read filekey.key
> MWpYeBrqiaVVZIOZrJFntiF2K0_ZYZZ2eCxBQ1_CuAI=
```

## `create` : Create a filekey
Creates a filekey in the current folder by providing the desired name and the key (*base64 urlsafe*). 

**Practical example**: after encrypting a file, for security reasons we don't want to keep the filekey on the computer, so we can extract its key using the `read` command, copy/paste it somewhere else (or even copy it onto paper) and delete the filekey. When we want to decrypt this file, the filekey can be recreated using the `create` command.

**Example**

Create a file named 'secretkey' :

`python filecrypt.py create secretkey`

A confidential input field appears to receive the key:

`> Key: ***************************`

The command creates a filekey in the current folder, named `secret.key`, with the supplied key.

>**Note** : You don't need to specify the filekey extension, as it will automatically be saved in .key format for standardization reasons. Only the name is required.

## `timestamp` : Displays the timestamp of an encrypted file
This command extracts the timestamp of a Fernet token (*from an encrypted file*), i.e. the timestamp at which the file was encrypted. To do this, the command needs the name of the encrypted file in the current folder as well as the filekey used to encrypt it, or the password.

**Example**

Here are examples of the two different methods: 
1. By using a file encrypted with a filekey
2. By using a file encrypted with a password

Here, we want to extract the timestamp from an encrypted file named `image.jpg`

**Method 1** : By using a file encrypted with a filekey
`python filecrypt.py timestamp image.jpg -f filekey.key`

**Method 2** : By using a file encrypted with a password
`python filecrypt.py timestamp image.jpg -p`

A confidential input field appears to receive the password:

`> Password: *************`

The salt is recovered automatically from the file.

**Output** :
```
- - - - - - - - - - - - - - - - - - - -
image.jpg was encrypted at : 2024-12-01 18:35:59
Since 2 hours, 9 minutes, 3 seconds
Timestamp : 1733074559
- - - - - - - - - - - - - - - - - - - -
```

## `copykey` : Copy a filekey's Base64 key to the clipboard
Allows copying the base64 key of a filekey located in the current folder to the clipboard. This can be useful for retrieving the secret key without displaying it directly on the terminal.

**Exemple**

```
> python filecrypt.py copykey filekey.key
Key copied to clipboard.
Don't forget to clean the clipboard after use ('clean' command).
```

## `getsalt` : Extract the salt from a password-encrypted file
Reads the first 16 bytes of a password-encrypted file and displays the embedded salt as a base64 urlsafe string. This command is useful for inspection, archiving, or debugging purposes. It does not decrypt anything and requires no password.

> **Note**: The salt is public by nature. Its value alone, without the password, is cryptographically useless. Displaying or copying it carries no security risk.

**Options**

- `-cs` / `--copysecret` : copies the extracted salt to the clipboard.

**Example**

```
python filecrypt.py getsalt image.jpg
> Salt: gbprPvZg8NIBMOxKae7z1vVJLOiFzj5=
```

With copysecret option:
```
> python filecrypt.py getsalt image.jpg -cs
Salt: gbprPvZg8NIBMOxKae7z1vVJLOiFzj5=
Salt copied to clipboard.
Don't forget to clean the clipboard after use ('clean' command).
```

## `verify` : Verify that a key/password can decrypt a file
The command checks if a filekey or a password can decrypt a file without writing to the disk. In password mode, the salt is recovered automatically from the file.

**Example**

With a filekey:
```
> python filecrypt.py verify encrypted_image.jpg filekey.key
✓ Verification successful.
Filekey 'filekey.key' can decrypt 'encrypted_image.jpg'.
```

With a password:
```
> python filecrypt.py verify encrypted_image.jpg -p
Password:
✓ Verification successful.
The given password can decrypt 'encrypted_image.jpg'.
```

## `clean` : Clear the clipboard
The command replaces the current clipboard with an empty entry to reduce the risk of confidential data such as passwords or secret keys leaking out, as the user may eventually have to copy/paste these values.

**Example**
```
python filecrypt.py clean
> The clipboard has been erased
```

> **Linux users** : Some Linux distributions may have restrictions on accessing the clipboard; several attempts not requiring automatic package installation will be made; if these fail, the user will be informed of the packages to install.

## `delete` : Delete files/folders securely
The command is used to **securely delete** files/folders from the current folder. To achieve this, before being removed by the `os.remove` method, the file is blindly encrypted several times (*without the keys being communicated*) with a new random key on each pass. After this, the file is truncated to its original size.

**Options**:

- `-s` / `--shuffle`: File bytes are shuffled just before the deletion

> **Secure deletion**: Secure deletion most often means overwriting the contents of a file several times with random data before deleting it, making recovery much more difficult. This involves different procedures for Linux and Windows. While Linux has a special command for this kind of operation (`shred`), Windows requires the installation of a specific Microsoft utility (`sdelete`). To compensate for this and preserve the script's portability and lightness, the command **uses the encryption functions already present in the script** to make the file unreadable before deletion, even for the user.

> **Note**: All deletions must be explicitly confirmed by the user, but filekeys are treated in a special way: the user is asked to ensure that he has kept a copy of the key in a safe place.

> **Encryption passes**: The file size will temporarily increase with each encryption pass. Even if the file returns to its initial size after the truncation phase, setting the number of passes to 2 seems a more than acceptable compromise, particularly for large files.

**Examples**

Let's suppose we want to delete the file 'image.jpg' in the current folder :
```
python filecrypt.py delete image.jpg
> You are about to irreversibly delete the file 'image.jpg'
> File size: 39.64 ko
> From: C:\Users\Bob\Code\image.jpg
> Do you confirm this operation? (y/n): y # user input
> Encryption...
> Pass 1/2 completed.
> Pass 2/2 completed.
> Resizing...
> 'brain.jpg' has been deleted.
```
Same example with the `-s` \ `--shuffle` option:
```
python filecrypt.py delete image.jpg -s
> You are about to irreversibly delete the file 'image.jpg'
> File size: 39.64 ko
> From: C:\Users\Bob\Code\image.jpg
> Do you confirm this operation? (y/n): y # user input
> > Encryption...
> Pass 1/2 completed.
> Pass 2/2 completed.
> Resizing...
> Shuffling...
> 'filekey.key' has been deleted.
```
> **Note**: The shuffle operation can be long for large files (approx. 2 min on a standard PC for a 100MB file).

Multiple deletion:
```
python filecrypt.py delete secret.txt image.jpg 
> You are about to irreversibly delete the following targets:
> [file]   secret.txt
> [file]   image.jpg
> Do you confirm this operation? (y/n): y # user input
> 'secret.txt' has been deleted.
> 'image.jpg' has been deleted.
```
Folder deletion:
```
python filecrypt.py delete my_folder
> You are about to irreversibly delete the folder 'my_folder' and all its contents.
> From: C:\Users\Bob\Code\my_folder
> Files to delete: 3
> Do you confirm this operation? (y/n): y # user input
> Processing folder 'my_folder'...
> Folder 'my_folder' has been deleted.
```

## `zip` : Zip files/folders
The command is used to compress files or folders in the current folder into `.zip` format. The command may be useful if the user wants to encrypt an entire folder.

**Options**:

- `-d` / `--delete`: Securely deletes the original file/folder after compression, after user confirmation.

**Examples**

Let's suppose we want to zip the file 'image.jpg'.
```
python filecrypt.py zip image.jpg
> Zipping...
> Added : image.jpg
> 'brain.jpg' compressed successfully.
```
A zip archive named 'image.zip' is created in the current folder. Since the `--delete` option isn't enabled, the original file remains in the current folder.

Now let's suppose we want to compress a folder called 'secret' with this tree structure.

```
secret/
├─ fold1/
│  ├─ psw.txt
│  ├─ salt.txt
├─ fold2/
│  ├─ ciphertext.txt
│  ├─ key.txt

```
We also want this folder to be securely deleted after compression, so we activate the `-d` / `--delete` option :

```
python filecrypt.py zip secret -d
> Compression will delete the 'secret' folder.
> From: C:\Users\Bob\Code\secret
> Do you confirm the operation ? (y/n): y # User input
> Zipping...
> Added: secret\fold1\psw.txt
> Added: secret\fold1\salt.txt
> Added: secret\fold2\ciphertext.txt
> Added: secret\fold2\key.txt
> Deleting files...
> File deletion 1/4
> File deletion 2/4
> File deletion 3/4
> File deletion 4/4
> 'secret' compressed successfully. 
```
Multiple zip
```
python filecrypt.py zip image.jpg my_folder
> Zipping...
> Added : image.jpg
> Added: my_folder/two.txt
> Added: my_folder/one.txt
> 'archive.zip' created successfully.
```

## `unzip` : Unzip files/folders
The command unzips zip archives in the current folder.

**Example**

Unzipping the 'secret.zip' archive :
```
python filecrypt.py unzip secret.zip
> Unzipping secret.zip...
> secret.zip extracted successfully.
```

# Some technical details
## What's Fernet ?
Fernet (from `cryptography` module) is an implementation of the AES algorithm using a 128-bit key. Fernet offers an abstraction that allows developers to encrypt and decrypt data without having to worry about the complexities of implementing AES and other security mechanisms.

## What level of security?
* **AES** : Data is encrypted using AES (**A**dvanced **E**ncryption **S**tandard), a symmetrical encryption algorithm that encrypts data in blocks of a fixed size.


* **128-bits** : This is the size of the secret key. It offers a high level of security, making brute-force attacks extremely difficult ($2^{128}$ possible combinations).


* **CBC mode** : The **C**ipher **B**lock **C**haining links the encryption of each block to the previous one. Each block of plaintext data is XOR'd with the preceding encrypted block before being encrypted. So if a bit is modified in the ciphertext, this will affect not only the decryption of this block, but also of all subsequent blocks.


* **Initialisation Vector (IV)** : Since the first block has no precedent, it's subjected to a random initialization vector: a series of randomly generated bits of the same size as the block, which acts as the “previous block”. This randomness masks repetitions in the code, even if the plain text begins with the same data in several sessions.


* **Crypto secure RNG** : The secret key and the initialisation vector are randomly generated using `os.urandom()`, which relies on the operating system's entropy (*harware interupts, network data, running processes...*) to make generation as unpredictable as possible (CSPRNG).


* **Padding PKCS7** : This technique ensures that the data to be encrypted always occupies an integer number of blocks, as required by the AES algorithm. To do this, the function adds padding bytes to the end of the plaintext data if it isn't a multiple of the desired block size.


* **HMAC** : **H**ash-based **M**essage **A**uthentication **C**ode is a cryptographic function used to verify the integrity and authenticity of a message (Token), it's calculated on the basis of the encrypted data. **If the integrity of the encrypted file is compromised, it becomes impossible to decrypt it**.


* **SHA-256** : A cryptographic hash function that produces a 256-bit hash value. It's used to generate the **M**essage **A**uthentication **C**ode.

* **Password & Salt** : Data can be encrypted using a user-memorable password, which is **derived** to produce a 128-bit key. Before being hashed, this password is "mixed" with a sequence of random bytes called a "**salt**". The `psw` command (*see above*) allows the user to generate secure passwords. The salt is generated automatically by the script and embedded in the encrypted file — the user never needs to handle it directly.


* **Key derivation** : principle of using a single secret key (*often called the master key, represented here by our password*) to generate several different keys of any desired length (*using an algorithm, PBKDF2 in our case*). To create these new keys, we generally use cryptographic hash functions. These functions take as input the master key (*our password*) and other information, such as the salt, to produce as output a unique and difficult-to-invert value, which will be our new key. This method has several advantages:
  - **Security** : By having several derived keys, we limit the risks if one key is compromised. If an attacker discovers one of the derived keys, he won't have access to the master key and therefore to the other keys
  - **Flexibility** : We can generate specific keys for different operations, allowing to tailor our security system to our needs.
  - **Efficiency** : Instead of storing and managing several independent keys, we can store a single master key and generate the other keys as needed.
  - **Practicality** : Since we can't decently ask the user to enter a memorable 128-bit password from memory, key derivation overcomes this problem by matching the inserted password to the required security standards.


* **Salt** : Imagine you want to preserve a dish with a unique taste. To make it inimitable, you can add a pinch of specific salt to your recipe. This salt, unique to your dish, will make it impossible for anyone else to reproduce exactly the same taste using the same basic ingredients. In cryptography, the "salt" plays a similar role. It's a random sequence of bytes added to a password before it's hashed. This prevents two identical passwords from producing the same derived key, and makes precomputed dictionary attacks (rainbow tables) ineffective.

  The salt is **not a secret**: its value alone, without the password, provides no advantage to an attacker. For this reason, the script embeds it directly in the encrypted file rather than asking the user to store it separately.


> <span style="color:red"><b>Safety reminder</b></span> : The security of a password-encrypted file rests entirely on the **password**. The salt is public and embedded in the file — only the password must be kept safe. An attacker in possession of the encrypted file already has access to the salt; what prevents decryption is not knowing the password.

## Key and token
The key and the token are two key concepts used by Fernet to encrypt and decrypt data.

### Key
A 256-bit key (32 bytes), randomly generated and used to encrypt and decrypt data. The key is divided into two parts: an **encryption key** and a **signing key**, each 128 bits (16 bytes) long. This division is at the heart of Fernet's cryptographic mechanism, which combines encryption and authentication.

* **Key format** : A base64url key with the following fields:
  * **Signing-key, (128 bits)** : used to calculate cryptographic authentication (HMAC) on the token (*the encrypted data*). Indeed, token authentication is based not only on the ciphertext (*and other metadata*), but also on the signing-key. This ensures that the person decrypting the file actually owns the original key.

  * **Encryption-key, (128 bits)** : used by the AES algorithm in CBC (Cipher Block Chaining) mode to transform plaintext data into ciphertext data.
  
  So, if the encryption-key part is modified, decryption becomes impossible, and if the signing-key part is modified, the token's HMAC is no longer valid, and here again, decryption is impossible.

### Token
A data container encapsulating everything needed to decrypt the data or verify its integrity.

* **Token format** : Coded in base64 urlsafe, it contains the following fields:

  * **Version, (8 bits)** : denotes which version of the format is being used by the token. Currently there is only one version defined, with the value 128 (0x80)

  * **Timestamp, (64 bits)** : a 64-bit unsigned big-endian integer. It records the number of seconds elapsed between January 1, 1970 UTC and the time the token was created

  * **Initialisation Vector (IV), (128 bits)** : the 128-bit Initialization Vector (see above) used in AES encryption and decryption of the Ciphertext. When generating new fernet tokens, the IV must be chosen uniquely for every token. With a high-quality source of entropy, random selection will do this with high probability.

  * **Ciphertext, variable length, (multiple of 128 bits)** : has variable size, but is always a multiple of 128 bits, the AES block size. It contains the original input message, padded and encrypted.

  * **HMAC, (256 bits)** : (**H**ash-based **M**essage **A**uthentication **C**ode) used to authenticate the token, i.e. the header (*version and timestamp*), the ciphertext and the IV. This authentication key is calculated using the signing-key as the secret key. Thus, HMAC ensures not only integrity, but also authenticity.

## Script SAFE_MODE
The script is able to modify or even deleting files/folders, so its use is controlled to reduce the risk of inadvertent manipulation. To do this, the script checks whether its location corresponds to a **sensitive area of the system**. If this is the case, SAFE_MODE mode is activated, preventing the call of file/folder modifying functions. In addition, the script can only access files/folder located in its current folder, in this way, even if the script is in a “safe” area of the system, it cannot reach a path outside its current folder.

> Zones considered “sensitive” depend on the user operating system and are defined in the `in_danger_zone` function.

Commands **not accessible** in SAFE_MODE :
- encrypt
- decrypt
- delete
- zip
- unzip
- create

Commands **still accessible** in SAFE_MODE :
- install
- psw
- read
- timestamp
- getsalt
- copykey
- verify
- clean