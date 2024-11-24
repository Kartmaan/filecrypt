import subprocess
import argparse
import sys
from os import remove
from os.path import exists
import string
import shutil

from cryptography.fernet import Fernet, InvalidToken

FILEKEY_EXT = ".key"

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

def valid_filename(file_name: str) -> bool:
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

def valid_filekey_name(filekey: str) -> bool:
    """Checks the validity of a filekey. 

    Args:
        filekey (str): Filekey path

    Returns:
        bool: Valid or not
    """    
    if not exists(filekey):
        print(f"{filekey} not found")
        return False
    
    if not filekey.endswith(FILEKEY_EXT):
        print(f"Filekey must be {FILEKEY_EXT}")
        return False
    
    return True

def read_filekey(filekey: str):
    """Displays the Base64 code of a filekey

    Args:
        filekey (str): Filekey path
    """    
    if exists(filekey):
        if filekey.endswith(FILEKEY_EXT):
            with open(filekey, "r") as f:
                content = f.read()
                print(content)
        else:
            print(f"Filekey must be {FILEKEY_EXT}")
    else:
        print(f"{filekey} not found")

# <WORK IN PROGRESS>
def create_filekey(file_name: str, base64_code: str):
    if not valid_filename(file_name):
        print("Invalid file name")
        return None
    if exists(file_name):
        print(f"{file_name} already exists")
        return None    
# </WORK IN PROGRESS>

def encrypt(filename: str, overwrite:bool = True, 
            given_filekey = None):
    """Encrypts a file and generates a secret key

    Args:
        filename (str): File name to encrypt
        overwrite (bool, optional): Overwrite the file to 
        encrypt. Defaults to True.

    Returns:
        None: If an error has been encountered
    """    
    print(f"---- Encryption of {filename} ----")

    # No filekey given, a random key will be generated.
    # --keyfile = False
    if given_filekey == None:
        generated_filekey_name = 'filekey' + FILEKEY_EXT

        # If a 'filekey.key' file already exists in the 
        # current folder, the user is prompted to choose 
        # another name for the key to be generated.
        while exists(generated_filekey_name):
            choice = input(f"{generated_filekey_name} already " 
            "exists in the current folder, choose another name" 
            " (without extension): ")

            if valid_filename(choice):
                generated_filekey_name = choice + FILEKEY_EXT
            else:
                print("Invalid file name, please avoid spaces"
                " and symbols")
                continue

        # Filekey generation
        print(f"Filekey generation ({generated_filekey_name})...")
        key = Fernet.generate_key()
        with open(generated_filekey_name, 'wb') as filekey:
            filekey.write(key)
    
    # FILEKEY GIVEN
    else:
        if valid_filekey_name(given_filekey):
            generated_filekey_name = given_filekey
        else:
            return None

    # Filekey reading and retrieved as bytes
    if given_filekey == None:
        print("Generated filekey reading...")
    else:
        print(f"Given filekey reading ({generated_filekey_name})...")

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
    if given_filekey == None:
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

    if not valid_filekey_name(filekey_name):
        return None

    # Filekey reading and retrieved as bytes
    print(f"Filekey reading ({filekey_name})...")
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

def main():
    """The argparse structure is defined, as are its call 
    logics
    """
    # - - - - - - Argparse structure - - - - - -
    
    # Main parser
    parser = argparse.ArgumentParser(
        description="Script to encrypt/decrypt files "
        "using Fernet"
    )

    # Sub-commands
    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands"
    )

    # - - - - - - Command : install
    parser_install = subparsers.add_parser(
        "install",
        help="Install dependencies using pip"
    )

    # - - - - - - Command : read
    parser_read = subparsers.add_parser(
        "read",
        help="Read a keyfile encoded in Base64"
    )
    parser_read.add_argument(
        "filekey",
        help="Path to keyfile"
    )

    # - - - - - - Command : encrypt
    parser_encrypt = subparsers.add_parser("encrypt",
        help= "Encrypts a file")
    parser_encrypt.add_argument("filename",
        help= "Path of file to be encrypted")
    parser_encrypt.add_argument("-f", "--filekey",
        help= "Path of the existing filekey", default=None)
    
    # The -overwrite and -copy options are mutually 
    # exclusive, only one of them can be called.
    # Choosing either option is mandatory
    group_encrypt = parser_encrypt.add_mutually_exclusive_group(required=True)
    group_encrypt.add_argument("-ow", "--overwrite", 
        action="store_true", help= "Overwrites the file")
    group_encrypt.add_argument("-c", "--copy",
        action="store_true", help= "Copy the plain-text file "
        "before overwriting it in its encrypted version")
    
    # - - - - - - Command : decrypt
    parser_decrypt = subparsers.add_parser("decrypt",
        help= "Decrypts a file")
    parser_decrypt.add_argument("filename", 
        help= "Path to the file to decrypt")
    parser_decrypt.add_argument("filekey",
        help= "The filekey containing the secret key for" 
        " decrypting the file")
    
    # - - - - - - Call logics - - - - - -
    args = parser.parse_args()

    if args.command == "install":
        install_from_requirements()
    
    elif args.command == "read":
        read_filekey(args.filekey)
    
    elif args.command == "encrypt":
        if args.overwrite and not args.copy:
            encrypt(args.filename, True, args.filekey)
        elif args.copy and not args.overwrite:
            encrypt(args.filename, False, args.filekey)
        else:
            print("ERROR")
    
    elif args.command == "decrypt":
        decrypt(args.filename, args.filekey)
    
    else:
        print("ERROR : Unknown argument")
        
if __name__ == "__main__":
    main()