import subprocess
import sys
from os import remove
from os.path import exists
import string
import shutil

from cryptography.fernet import Fernet, InvalidToken

def install_from_requirements(requirements_file="requirements.txt"):
    """
    Installs modules listed in a txt file.

    Args:
        requirements_file (str, optionnal): The path to 
        the file. By default, searches for requirements.txt 
        in the current folder.
    """

    try:
        # Opens the file in read mode
        with open(requirements_file, 'r') as f:
            for line in f:
                # Removes spaces and comments
                package = line.strip()
                if package and not package.startswith('#'):
                    try:
                        # Tries to install the package with pip
                        print(f"Checking and installing the package : {package}")
                        subprocess.check_call([sys.executable, "-m", 
                            "pip", "install", package])
                        print(f"{package} has been successfully installed.")
                    except subprocess.CalledProcessError:
                        print(f"Error: Unable to install {package}.")

    except FileNotFoundError:
        print(f"{requirements_file} not found.")
    except Exception as e:
        print(f"An unexpected error has occurred : {e}")

def file_name_checker(file_name: str) -> bool:
    """Checks if a file name is valid by checking whether 
    all its characters are in a whitelist.

    Args:
        file_name (str): Name of the file to be checked

    Returns:
        bool: Valid or not
    """

    # Whitelist composed of letters, numbers and the 
    # underscore symbol
    symbols = ['_']
    letters_digits = list(string.ascii_letters + 
    string.digits)
    whitelist = symbols + letters_digits

    # Not a str (unlikely in the context of this script, 
    # but who knows?)
    if not isinstance(file_name, str):
        return False

    # The string is too long
    if len(file_name) > 255:
        return False
    
    # Iteration to search for a character not in the 
    # whitelist
    for char in file_name:
        if char not in whitelist:
            return False
    
    # Seems ok
    return True

def encrypt(filename: str, overwrite:bool = True):
    """Encrypts a file and generates a secret key

    Args:
        filename (str): File name to encrypt
        overwrite (bool, optional): Overwrite the file to 
        encrypt. Defaults to True.

    Returns:
        None: If an error has been encountered
    """    
    print(f"---- Encryption of {filename} ----")

    generated_filekey_name = 'filekey.key'

    # If a 'filekey.key' file already exists in the 
    # current folder, the user is prompted to choose 
    # another name for the key to be generated.
    while exists(generated_filekey_name):
        choice = input(f"{generated_filekey_name} already " 
        "exists in the current folder, choose another name" 
        " (without extension): ")

        if file_name_checker(choice):
            generated_filekey_name = choice + '.key'
        else:
            print("Invalid name file, please avoid spaces"
            " and symbols")
            continue

    # Filekey generation
    print("Filekey generation...")
    key = Fernet.generate_key()
    with open(generated_filekey_name, 'wb') as filekey:
        filekey.write(key)
    
    # Filekey reading and retrieved as bytes
    print("Filekey reading...")
    try:
        with open(generated_filekey_name, 'rb') as filekey:
            key = filekey.read() # key = bytes
    except FileNotFoundError:
        print(f"Error : No such keyfile : {filename} in the current folder")
        return None

    # Fernet object creation with the generated key
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
    print(f"Encrypted data writing...")
    with open(filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    
    print("---- Operation completed successfully ----")
    print("A keyfile.key file has been generated in the current folder,"
    " please keep it safe")

def decrypt(filename: str, filekey_name: str):
    """Decrypts a file using a secret key 

    Args:
        filename (str): Name of file to be decrypted
        filekey_name (str): Secret key to use for decryption

    Returns:
        None: If an error has been encountered
    """        
    print(f"---- Decryption of {filename} ----")

    # Filekey reading and retrieved as bytes
    print("Filekey reading...")
    try:
        with open(filekey_name, 'rb') as filekey:
            key = filekey.read() # key = bytes
    except FileNotFoundError:
        print(f"Error : No such filekey : '{filekey_name}'"
        " in the current folder")
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
    try :
        decrypted = f.decrypt(encrypted)
    except InvalidToken:
        print("Error : Invalid keyfile")
        return None

    # Overwriting the file with decrypted bytes data
    # File regains its integrity
    print(f"{filename} writing...")
    with open(filename, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

    print("Operation completed successfully")

if __name__ == "__main__":
    # INSTALL
    if len(sys.argv) == 2 and sys.argv[1] == 'install':
        install_from_requirements("requirements.txt")

    # ENCRYPT
    # 1 - encrypt
    # 2 - filename
    # 3 - ow - c
    elif len(sys.argv) == 4 and sys.argv[1] == 'encrypt':
        if sys.argv[3] == 'ow': # Overwriting
            encrypt(sys.argv[2], overwrite=True)
        elif sys.argv[3] == 'c' : # Copy before overwriting
            encrypt(sys.argv[2], overwrite=False)
        else: # ERROR
            print("Error : last argument of encrypt function must" 
            " be 'ow' or 'c'")

    # DECRYPT
    # 1 - decrypt
    # 2 - filename
    # 3 - filekey
    elif len(sys.argv) == 4 and sys.argv[1] == 'decrypt':
        decrypt(sys.argv[2], sys.argv[3])

    # ARGS ERROR
    else:
        print("Error : Wrong arguments, parameters order must be :")
        print("- encrypt <filename> ow/c")
        print("- decrypt <filename> keyfile_name")
        print("- install")
        