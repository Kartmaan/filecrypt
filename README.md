# Filecrypt
This Python script intended to be executed on the command line, allows to **encrypt and decrypt files present in the current folder of the script**. The program is based on the `cryptography` module and in particular its Fernet class allowing symmetric encryption using the 128-bit AES algorithm.

## `encrypt` funtion
Allows to encrypt a file found in the script's **current folder**. Before encrypting the file, the program generates a `filekey.key` file containing the randomly generated secret key from which the file will be encrypted. **This file is to be kept preciously** in order to be able to decrypt the file later and prevent the file from being read by others.

The function must take two arguments:
- The name of the file to encrypt (with its extension)
- The choice of procedure: 
  - `ow` : the file will be overwritten, in the case of an image file for example, it will therefore become unusable (corrupted) in its encrypted form
  - `c` : the file will be copied to the current folder before being overwritten

Case examples for psw.txt file encryption :

**Overwrite mode** :

`python filecrypt.py encrypt psw.txt ow`

**Copy mode** :

`python filecrypt.py encrypt psw.txt c`

The encryption operation will leave a `filekey.key` file in the current folder which must be kept safe

## `decrypt` function
Used to decrypt a file found in the current folder using a key file also present in the folder and in which the secret key is located. The function must take 2 parameters :
- The name of the file to decrypt (with its extension)
- The name of the key file present in the current folder (with its extension)

Case examples for psw.txt file decryption :

`python filecrypt.py decrypt psw.txt filekey.key`
