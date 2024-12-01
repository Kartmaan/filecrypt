import argparse
import base64
from datetime import datetime as dt
from dateutil.relativedelta import relativedelta
from os import remove, urandom
from os.path import exists
from shutil import copyfile
from string import ascii_letters, digits
import subprocess
import sys
import time
from typing import Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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

def valid_b64_urlsafe(b64_code: Union[str, bytes]) -> bool:
    """Checks if the entry is a valid base64 urlsafe code.

    Fernet manipulates keys in the form of base64 urlsafe
    code, so we'll make sure the input respects this format.

    Args:
        b64_code (Union[str, bytes]): Entry to check

    Returns:
        bool: Valid base64 urlsafe or not
    """
    try:
        base64.urlsafe_b64decode(b64_code)
        return True
    except Exception:
        return False

def valid_filename(file_name: str) -> bool:
    """Checks if a file name is valid including by checking
    if all its characters are in a whitelist.

    Args:
        file_name (str): Name of the file to be checked

    Returns:
        bool: Valid or not
    """

    # Whitelist composed of letters, numbers and the
    # underscore symbol
    symbols = ['_']
    letters_digits = list(ascii_letters + digits)
    whitelist = symbols + letters_digits

    # Not a str (unlikely in the context of this script,
    # but who knows?)
    if not isinstance(file_name, str):
        print("File name must be a str")
        return False

    # The string is too long
    if len(file_name) > 255:
        print("File name too long")
        return False

    # Iteration to search for a character not in the
    # whitelist
    for char in file_name:
        if char not in whitelist:
            print("Invalid char in file name")
            return False

    # Seems ok
    return True

def valid_filekey_name(filekey: str, create: bool = False) -> bool:
    """Checks the validity of a filekey name.

    The definition of a valid file key name depends on
    whether the file key is supposed to be present in the
    current folder or created by the user.

    Args:
        filekey (str): Filekey path

        create (bool): Is the filekey supposed to be
        created or not (i.e. found in the current folder)?

    Returns:
        bool: Valid filekey name or not
    """
    if not isinstance(filekey, str):
        print(f"Wrong type, must be a str ({type(filekey)}"
        " given)")
        return False

    # - The filekey will be recovered -
    # We are looking for a filekey that is supposed to be
    # already present in the current folder. We make sure
    # the file exists and has the right extension
    if not create:
        if not exists(filekey):
            print(f"{filekey} not found")
            return False

        if not filekey.endswith(FILEKEY_EXT):
            print(f"Filekey must be {FILEKEY_EXT}")
            return False

    # - The filekey will be created -
    # We make sure no file with the same name exists
    else:
        if not valid_filename(filekey):
            return False
        
        if exists(filekey + FILEKEY_EXT):
            print(f"{filekey} already exists")
            return False

    return True

def valid_filekey_key(filekey: str) -> Union[bool, None]:
    """Checks whether the key present in a filekey is valid.

    Args:
        filekey (str): Given filekey

    Returns:
        Union[bool, None]: Returns True/False if
        verification was successful. None otherwise.
    """
    with open(filekey, "r") as f:
        content = f.read()

    if not valid_b64_urlsafe(content):
        return False
    else:
        return True

def valid_filekey(filekey: str) -> bool:
    """Checks the validity of a filekey's name as well as 
    its contents

    Args:
        filekey (str): Filekey name (with extension)

    Returns:
        bool: _description_
    """    
    if valid_filekey_name(filekey) and valid_filekey_key(filekey):
        return True
    else:
        return False

def valid_password(psw: str) -> bool:
    """Checks the validity of a password.

    Args:
        psw (str): The given password

    Returns:
        bool: Valid or not
    """ 
    MIN_LENGTH = 5
    blacklist = [' ']

    if not isinstance(psw, str):
        print("psw must be a str type")
        return False

    if len(psw) < MIN_LENGTH:
        print(f"Password must be at least {MIN_LENGTH} "
              "characters long")
        return False
    
    for char in psw:
        if char in blacklist:
            return False

    return True

def valid_salt(salt: str) -> bool:
    """Checks the validity of a salt, which must be 
    base64-encoded.

    Args:
        salt (str): The given salt value

    Returns:
        bool: Valid or not
    """
    if len(salt) == 0:
        print("No salt value inserted")
        return False
    
    # No space
    salt = salt.replace(' ', '')
       
    try:
        salt_ok = base64.urlsafe_b64decode(salt)
        return True
    except (ValueError, TypeError):
        print("Invalid salt, must be a b64")
        return False

def read_filekey(filekey: str, return_value: bool = False) -> Union[str, None]:
    """Displays or returns the Base64 key of a filekey.

    Args:
        filekey (str): Filekey with extension

        return_value (bool): If True, the 'content'
        variable is returned, otherwise it's simply
        displayed (optional).
    
    Return:
        str : The b64 key
        None : Error
    """

    if valid_filekey(filekey):
        with open(filekey, "r") as f:
                content = f.read()
                if not return_value:
                    print(content)
                else:
                    return content
    else:
        return None

def create_filekey(file_name: str, key: str) -> None:
    """Creates a filekey based on a base64 key.

    If the key is valid, this filekey can be used to 
    encrypt and decrypt data. 

    Args:
        file_name (str): Desired name for filekey without
        extension

        key (str): Secret key (base64 urlsafe)
    
    Return:
        None : If an error has occurred
    """

    if not valid_filename(file_name):
        return None

    if not valid_filekey_name(file_name, create = True):
        return None

    # No spaces
    key = key.replace(' ', '')
    key_bytes = bytes(key, 'ascii')

    if valid_b64_urlsafe(key_bytes):
        with open(file_name + FILEKEY_EXT, 'wb') as f:
            f.write(key_bytes)
        print(f"{file_name + FILEKEY_EXT} has been created in the current folder")
    else:
        print("Invalid key, must be base64 urlsafe")
        return None

def since_when(token_timestamp: int) -> Union[str, None]:
    """Returns the elapsed time between an inserted 
    timestamp and the current one. The function returns 
    the elapsed time by units of time in a readable form.
    Example : "2 days, 1 hour, 22 minutes, 6 seconds"

    The function uses the 'relativedelta' method from 
    'dateutil' module to take into account the variable 
    length of months and years.

    Args:
        token_timestamp (int): The given timestamp

    Returns:
        str: Text of the elapsed time.
        None: Error.
    """

    # Invalid timestamp
    if not isinstance(token_timestamp, int) or token_timestamp <= 0:
        raise ValueError("Error: invalid timestamp, must be a positive integer")
    
    now = dt.now()

    # Time travellers are not allowed to use this feature.
    if token_timestamp > now.timestamp():
        raise ValueError("Error: the timestamp cannot be in the future.")
    
    # Elapsed time calculation
    datetime_token = dt.fromtimestamp(token_timestamp)
    delta = relativedelta(now, datetime_token)
    
    # Time units
    years = delta.years
    months = delta.months
    days = delta.days
    hours = delta.hours
    minutes = delta.minutes
    seconds = delta.seconds

    # We place these values in a dictionary so that we 
    # can easily browse them to display only those time 
    # units whose value is not zero.
    delta_dict = {
        "year" : years, "month" : months, "day" : days,
        "hour" : hours, "minute" : minutes, 
        "second" : seconds
    }

    # The dictionary is browsed for time units with a 
    # non-zero value. If the value is greater than 1, 
    # an 's' is added after the unit to make it plural.
    parts = [f"{val} {key}{'' if val == 1 else 's'}"
             for key, val in delta_dict.items() if val != 0]
    
    # Very fast user
    if not parts:
        return "Just now"

    return ", ".join(parts)

def get_timestamp(encrypted_file: str, 
                  filekey: Union[str, None] = None,
                  psw: Union[str, None] = None, 
                  salt: Union[str, None] = None) -> None:
    """Returns the timestamp for the token 

    Args:
        encrypted_file (str): Encrypted file name present 
        in the current folder
    
    Return:
        int : The Unix timestamp of the token
    """
    if not exists(encrypted_file):
        print(f"{encrypted_file} not found")
        return None
    
    # From a file crypted with a filekey
    if filekey != None and (psw == None and salt == None):
        if not valid_filekey(filekey):
            return None

        with open(filekey, 'rb') as key_file:
            key = key_file.read()
        
        f = Fernet(key)
    
    # From a file crypted with a psw and a salt
    elif (psw != None and salt != None) and filekey == None:
        if valid_password(psw) and valid_salt(salt):
            f = psw_derivation(psw, salt)
        else:
            return None
    
    # ERROR
    else:
        print("Wrong args combinaison, must be :")
        print("encryted_file + filekey OR "
              "encypted_file + psw + salt")
        return None

    with open(encrypted_file, 'rb') as encrypted_data:
        token = encrypted_data.read()
    
    try:
        timestamp = f.extract_timestamp(token)
        readable_time = dt.fromtimestamp(timestamp)
        print("- - - - - - - - - - - - - - - - - - - -")
        print(f"{encrypted_file} was encrypted at " 
            f": {readable_time}")
        print(f"Since {since_when(timestamp)}")
        print(f"Timestamp : {timestamp}")
        print("- - - - - - - - - - - - - - - - - - - -")
    except Exception as e:
        print(e)

def psw_derivation(psw: str, salt: Union[str, None] = None) -> Fernet:
    """Creates a Fernet object with a given password and 
    a salt value.

    psw :
    Since we can't decently ask the user to enter a 
    memorable 128-bit password, the inserted password will 
    be derived in such a way as to comply with Fernet's 
    standards of use.

    salt :
    If no salt value is entered, a random value will be 
    generated.

    Args:
        psw (str): Desired name for filekey without
        extension.

        salt (str | None): Given salt value (optional)

    Return:
        Fernet: A Fernet objet to encrypt/decrypt
    """
    # The password must be handled in bianary form.
    psw = psw.encode('ascii')

    # No salt inserted, so a salt will be randomly 
    # generated. 
    if salt == None:
        salt = urandom(16) # 16 random bytes

        # The salt value is converted to b64 so that it 
        # can be displayed in a way that is readable 
        # enough for the user.
        salt_b64 = base64.urlsafe_b64encode(salt).decode('ascii')
        print("- - - - SALT (KEEP IT SAFE) - - - - -")
        print(f"{salt_b64}")
        print("- - - - - - - - - - - - - - - - - - -")

    # A salt has been inserted. Its validity is checked 
    # from the call functions (encrypt, decrypt). We expect 
    # a value of type b64 urlsafe
    else:
        salt = base64.urlsafe_b64decode(salt)

    # - - - - Derivation algorithm PBKDF2HMAC - - - -
    # * algorithm : Specifies the hash algorithm to be used 
    # for key derivation.
    #
    # * length : Determines the length of the generated key 
    # in bytes.
    #
    # * salt : Value, ideally random, to salt the password 
    # before hashing. This makes dictionary attacks and 
    # rainbow tables less effective.
    #
    # * iterations : Specifies the number of times the 
    # hash function will be applied. The higher the number,
    # the more difficult it is to break the password by 
    # brute force.
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 480000,
        )
    
    # The password is derived and combined with the 
    # previously specified parameters. The key is 
    # converted to b64 urlsafe to comply with Fernet 
    # standards
    key = base64.urlsafe_b64encode(kdf.derive(psw))
    f = Fernet(key)

    return f

def encrypt(filename: str, overwrite:bool = True, 
            given_filekey: Union[str, None] = None, 
            psw: Union[str, None] = None, 
            salt: Union[str, None] = None) -> None:
    """Encrypts a file in 3 different ways :

    1. By generating a random filekey in the current 
    folder
    2. By retrieving a filekey already present in the 
    current folder
    3. Based on a password and a salt

    These 3 methods are mutually exclusive

    Args:
        filename (str): File name to encrypt.

        overwrite (bool, optional): Overwrite the file to
        encrypt. Defaults to True.

        given_filekey (str | None): Name of the filekey 
        already present in the current folder for 
        encrypting with. Defaults to None.

        psw (str | None): Password to encrypt the file.
        Defaults to None.

        salt (str | None): Custom salt given to encrypt
        the file. Defaults to None.

    Returns:
        None: If an error has been encountered
    """
    print(f"---- Encryption of {filename} ----")

    # No password given : function will be dealing with a filekey
    if psw == None:
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
        if given_filekey != None:
            if valid_filekey(given_filekey):
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

    # Password given : function will be dealing without a 
    # filekey
    else:
        # Security checkpoint. The procedure will encrypt 
        # the file by overwriting it with a new salt value.
        # The operation is critical enough to attract the 
        # user's attention.
        if overwrite and (psw != None and salt == None):
            choice = ''
            available_choices = ['y', 'yes', 'n', 'no'] 

            while choice not in available_choices:
                choice = input("CAUTION: "
                "You are about to encrypt the file "
                f"{filename} by overwriting it " 
                "with a NEW randomly generated salt.\n"
                "The new salt value will be displayed after " 
                "confirmation and must be noted and kept carefully.\n" 
                "Do you confirm this operation? (y/n)")
                choice = choice.lower()

                if choice == 'n' or choice == 'no':
                    print("Operation cancellation...")
                    return None
                
                elif choice == 'y' or choice == 'yes':
                    pass

                else:
                    print("Wrong input")
                    continue

        # No salt entered, only password needs to be checked
        if salt == None:
            if valid_password(psw):
                f = psw_derivation(psw, salt)
            else:
                return None
        
        # A salt has been inserted, the password and salt 
        # must be verified.
        elif salt != None:
            if valid_password(psw) and valid_salt(salt):
                f = psw_derivation(psw, salt)
            else:
                return None

        # Who knows ?
        else:
            print("Unexpected error ('encrypt' with psw)")
            return None

    # Copying the file before overwriting it
    if overwrite == False:
        name = filename[:filename.find('.')]
        name += "(copy)"
        ext = filename[filename.find('.'):]
        copy_filename = name + ext
        print("File copy before overwriting...")
        try:
            copyfile(filename, copy_filename)
        except FileNotFoundError:
            print(f"Error : No such file : {filename} " 
                  "in the current folder")
            if psw == None:
                remove(generated_filekey_name)
            return None
        
    # Recovery the file to be encrypted in bytes
    print(f"{filename} reading...")
    try:
        with open(filename, 'rb') as file:
            file_bytes = file.read() # file_bytes = bytes
    except FileNotFoundError:
        print(f"Error : No such file : {filename} in the "
              "current folder")
        if psw == None:
            remove(generated_filekey_name)
        return None

    # Bytes data encryption
    print(f"Data encryption...")
    encrypted = f.encrypt(file_bytes)

    # Overwriting the file with encrypted bytes data
    print(f"Encrypted data writing...")
    with open(filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    print(f"---- Operation completed successfully ----")
    if given_filekey == None and psw == None:
        print("A keyfile.key file has been generated in the " 
              "current folder, please keep it safe")

def decrypt(filename: str,
            filekey_name: Union[str, None] = None, 
            psw: Union[str, None] = None, 
            salt: Union[str, None] = None) -> None:
    """Decrypts a file in 2 different ways :

    1. By using filekey present in the current folder
    2. By using a password and a salt

    These 2 methods are mutually exclusive.

    Args:
        filename (str): Name of file to be decrypted

        filekey_name (str | None): Name of the filekey 
        already present in the current folder for 
        decrypt with. Defaults to None.
        
        psw (str | None): Password to decrypt the file.
        Defaults to None.
        
        salt (str | None): Salt value given to decrypt
        the file. Defaults to None.

    Returns:
        None: If an error has been encountered
    """
    print(f"---- Decryption of {filename} ----")

    # No password given : function will be dealing with a filekey
    if psw == None:
        if not valid_filekey(filekey_name):
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

    # Password given : function will be dealing without a filekey
    else:
        if valid_password(psw) and valid_salt(salt):
            f = psw_derivation(psw, salt)
        else:
            return None

    # Recovery the file to be decrypted (bytes)
    print(f"{filename} reading...")
    try:
        with open(filename, 'rb') as encrypted_file:
            encrypted = encrypted_file.read() # encrypted = bytes
    except FileNotFoundError:
        print(f"Error : No such file : '{filename}' in the current folder")
        return None

    # File data decryption
    print("Decrypting data...")
    try :
        decrypted = f.decrypt(encrypted)
    except InvalidToken:
        print("Error : Invalid filekey")
        return None

    # Overwriting the file with decrypted bytes data
    # File regains its integrity
    print(f"{filename} writing...")
    with open(filename, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

    print(f"---- Operation completed successfully ----")

def main() -> None:
    """The argparse structure is defined, as are its call
    logics

    Returns:
        None: Error
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
    
    # - - - - - - Command : timestamp
    parser_timestamp = subparsers.add_parser(
        "timestamp",
        help="Extracts a timestamp from a token"
    )
    parser_timestamp.add_argument(
        "encrypted_file",
        help="Encrypted file name in the current folder"
    )
    parser_timestamp.add_argument(
        "-f", "--filekey",
        help="Filekey name in the current folder",
        default= None
    )
    parser_timestamp.add_argument(
        "-p", "--password",
        help="Password to decrypt the file",
        default= None
    )
    parser_timestamp.add_argument(
        "-s", "--salt",
        help="Salt to decrypt the file",
        default= None
    )

    # - - - - - - Command : create
    parser_create = subparsers.add_parser(
        "create",
        help="Create a new keyfile with a given key"
    )
    parser_create.add_argument(
        "filename",
        help="Filekey name"
    )
    parser_create.add_argument(
        "key",
        help="Key in base64 urlsafe"
    )

    # - - - - - - Command : encrypt
    parser_encrypt = subparsers.add_parser("encrypt",
        help= "Encrypts a file")
    parser_encrypt.add_argument("filename",
        help= "Path of file to be encrypted")
    parser_encrypt.add_argument("-f", "--filekey",
        help= "Path of the existing filekey", default=None)
    parser_encrypt.add_argument("-p", "--password", default= None,
        help= "Encrypts with a given password")
    parser_encrypt.add_argument("-s", "--salt", default= None,
        help= "Salt")

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
    parser_decrypt.add_argument("filekey", nargs="?",
        help= "The filekey containing the secret key for"
        " decrypting the file")
    parser_decrypt.add_argument("-p", "--password", default= None,
        help= "Decrypts with a given password")
    parser_decrypt.add_argument("-s", "--salt", default= None,
        help= "Salt")

    # - - - - - - Call logics - - - - - -
    args = parser.parse_args()

    if args.command == "install":
        install_from_requirements()

    elif args.command == "read":
        read_filekey(args.filekey)
    
    elif args.command == "timestamp":
        get_timestamp(
            encrypted_file=args.encrypted_file,
            filekey= args.filekey, psw= args.password,
            salt= args.salt)

    elif args.command == "create":
        create_filekey(args.filename, args.key)

    elif args.command == "encrypt":
        if (args.password and args.filekey):
            print("ERROR : You must provide either a 'filekey' or a "
                "'--password'.")
            return None

        elif args.overwrite and not args.copy:
            encrypt(args.filename, overwrite=True, 
                    given_filekey=args.filekey, 
                    psw=args.password, salt=args.salt)

        elif args.copy and not args.overwrite:
            encrypt(args.filename, overwrite=False, 
                    given_filekey=args.filekey, 
                    psw=args.password, salt=args.salt)

        else:
            print("ERROR")

    elif args.command == "decrypt":
        # Wrong command
        if (args.password is None and args.filekey is None) or (args.password and args.filekey):
            print("ERROR : You must provide either a 'filekey' or a "
                "'--password'.")
            return None

        # File must be decrypted with a password
        elif args.password:
            # Password derivation with a random salt
            if args.salt == None:
                decrypt(args.filename, psw=args.password)
            # Password derivation with a given salt
            else:
                decrypt(args.filename, psw=args.password, 
                        salt=args.salt)

        # File must be decrypted with a filekey
        else:
            decrypt(args.filename, args.filekey)

    else:
        print("ERROR : Unknown argument")

if __name__ == "__main__":
    main()