# Filecrypt
This Python script intended to be executed on the command line, allows you to encrypt and decrypt files present in the current folder of the script. The program is based on the "cryptography" module and in particular its Fernet class allowing symmetric encryption using the 128-bit AES algorithm.

Before encrypting the file, the program generates a "filekey.key" file containing the randomly generated secret key from which the file will be encrypted. This file is to be kept preciously in order to be able to decrypt the file later and prevent the file from being read by others.
