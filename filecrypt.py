import sys
from os import remove
import shutil
from cryptography.fernet import Fernet

def encrypt(filename, overwrite=True):
    """ Encrypt a file. 
    'filename' is the name of the file 
    to be encrypted present in the current script folder 
    (with its extension). For example from Powershell :

    python filecrypt.py encrypt img.jpg ow

    By default (overwrite=True) the file will be completely 
    rewritten in encrypted data and therefore will lose its 
    integrity, in the case of an image for example, 
    it will become corrupted. The command 'c' instead of 'ow' 
    allows to create a copy of the file in the current folder 
    before the overwrite operation :

    python filecrypt.py encrypt img.jpg c

    The function will first generate a "filekey.key" file in
    the current script folder in which is a randomly generated 
    secret key. This file should be kept safe
    """

    print(f"---- Encryption of {filename} ----")

    generated_filekey_name = 'filekey.key'

    # Filekey generation
    print("Filekey generation...")
    key = Fernet.generate_key()
    with open(generated_filekey_name, 'wb') as filekey:
        filekey.write(key)
    
    # Filekey reading and retrieved as bytes
    print("Filekey reading...")
    with open(generated_filekey_name, 'rb') as filekey:
        key = filekey.read() # key = bytes
    
    # Fernet object creation with key
    f = Fernet(key)

    # Copying the file before overwriting it
    if overwrite == False:
        name = filename[:filename.find('.')]
        name += "(copy)"
        ext = filename[filename.find('.'):]
        copy_filename = name + ext
        print("File copy before overwriting...")
        try:
            shutil.copyfile(filename, copy_filename)
        except FileNotFoundError:
            print(f"Error : No such file : {filename} in the current folder")
            remove(generated_filekey_name)
            return None

    # Recovery the file to be encrypted in bytes
    print(f"{filename} reading...")
    try:
        with open(filename, 'rb') as file:
            file_bytes = file.read() # file_bytes = bytes
    except FileNotFoundError:
        print(f"Error : No such file : {filename} in the current folder")
        remove(generated_filekey_name)
        return None
    
    # Bytes data encryption
    print(f"Data encryption...")
    encrypted = f.encrypt(file_bytes)

    # Overwriting the file with encrypted bytes data
    print(f"{filename} encryption...")
    with open(filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    
    print("Operation completed successfully")
    print("A keyfile.key file has been generated in the current folder, please keep it safe")

def decrypt(filename, filekey_name):
    """ Decrypt a file.
    'filename' is the name of the file 
    to be decrypted present in the current script folder 
    (with its extension)

    'keyfile_name' is the name of the keyfile (with its extension) 
    present in the current folder and from which the file can 
    be decrypted. Example with Powershell :

    python filecrypt.py decrypt img.jpg filekey.key
    """
    print(f"---- Decryption of {filename} ----")

    # Filekey reading and retrieved as bytes
    print("Filekey reading...")
    try:
        with open(filekey_name, 'rb') as filekey:
            key = filekey.read() # key = bytes
    except FileNotFoundError:
        print(f"Errpr : No such filekey : '{filekey_name}' in the current folder")
        return None
    
    # Fernet object creation with key
    f = Fernet(key)

    # Recovery the file to be decrypted in bytes
    print(f"{filename} reading...")
    try:
        with open(filename, 'rb') as encrypted_file:
            encrypted = encrypted_file.read() # encrypted = bytes
    except FileNotFoundError:
        print(f"Error : No such file : '{filename}' in the current folder")
        return None
    
    # Bytes data decryption
    print("Decrypting data...")
    decrypted = f.decrypt(encrypted)

    # Overwriting the file with decrypted bytes data
    # File regains its integrity
    print(f"{filename} decryption...")
    with open(filename, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

    print("Operation completed successfully")

if __name__ == "__main__":
    try:
        # ENCRYPT
        if sys.argv[1] == 'encrypt':
            if sys.argv[3] == 'ow': # Overwriting
                encrypt(sys.argv[2], overwrite=True)
            elif sys.argv[3] == 'c' : # Copy before overwriting
                encrypt(sys.argv[2], overwrite=False)
            else: # ERROR
                print("Error : last argument of encrypt function must be 'ow' or 'c'")

        # DECRYPT
        elif sys.argv[1] == 'decrypt':
            decrypt(sys.argv[2], sys.argv[3])

        # ERROR
        else:
            print(f"Error : The 1st argument must be 'encrypt' or 'decrypt'. Given : '{sys.argv[1]}'")
    
    except IndexError: # Wrong parameter order
        print("Error : parameters order must be :")
        print("- encrypt filename ow/c")
        print("- decrypt filename keyfile_name")