""" 
Filecrypt encrypts/decrypts files in the current folder 
using the AES algorithm via the Fernet implementation.

To do this, simply :
- Place this script in the folder containing the file(s) 
to be encrypted or decrypted.
- Go to this folder from the terminal.
- Call the script: 'python filescript.py' followed by the 
desired command.

Example : 'python filecrypt.py encrypt image.jpg -ow'

All information on available commands :
https://github.com/Kartmaan/filecrypt

Author : Kartmaan
Date : 2024-12-05
Version : 1.0.3
"""

import argparse
import base64
from datetime import datetime as dt
from dateutil.relativedelta import relativedelta
from os import remove, urandom
from os.path import exists
import secrets
from shutil import copyfile
from string import ascii_letters, ascii_lowercase
from string import ascii_uppercase, digits, punctuation
import subprocess
import sys
from typing import Union

REQUIREMENTS = ["cryptography", "pyperclip"]
FILEKEY_EXT = ".key"

def install_from_requirements():
    """
    Installs modules listed in the 'REQUIREMENTS' list with pip.
    """
    for package in REQUIREMENTS:
        try:
            # Tries to install the package with pip
            print(f"Checking and installing the package : {package}")
            subprocess.check_call([sys.executable, "-m",
                "pip", "install", package])
            print(f"{package} has been successfully installed.")

        except subprocess.CalledProcessError:
            print(f"Error: Unable to install {package}. Check your connection.")
            raise

        except Exception as e:
            print(f"An unexpected error has occurred : {e}")
            raise

# As these modules are not built-in, we insert them in a 
# try...except block to suggest that the user install 
# them if they are not present in his environment.
try :
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import pyperclip
except ImportError:
    choice = None

    while choice != "y" and choice != "n":
        print("One of the following modules isn't installed "
        f"in your environment: {REQUIREMENTS}.")

        choice = input("Do you want to install them ? (y/n): ")
        choice = choice.lower()

        if choice == "y":
            install_from_requirements()
            sys.exit(0)
        elif choice == "n":
            print("Exiting. Please install the missing " 
            "modules manually.")
            sys.exit(1)
        else:
            print("Invalid input")
            continue

def clean():
    """Deletes confidential data on the clipboard
    """
    pyperclip.copy("")
    print("The clipboard has been erased")

def valid_b64_urlsafe(b64_code: Union[str, bytes]) -> bool:
    """Checks if the entry is a valid base64 urlsafe code.

    Fernet manipulates keys in the form of base64 urlsafe
    code, so we'll make sure the input respects this format.

    Args:
        b64_code (Union[str, bytes]): Entry to check

    Returns:
        bool: Valid base64 urlsafe (True) or not (False)
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
        bool: Valid file name (True) or not (False)
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

    The definition of a valid filekey name depends on
    whether the filekey is supposed to be present in the
    current folder or created by the user.

    Args:
        filekey (str): Filekey path

        create (bool): Is the filekey supposed to be
        created or not (i.e. found in the current folder) ?
        Default to False. (optional)

    Returns:
        bool: Valid filekey name (True) or not (False)
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

def valid_filekey_key(filekey: str) -> bool:
    """Checks whether the key present in a filekey is valid.

    Args:
        filekey (str): Given filekey

    Returns:
        bool: Valid key (True) or not (False).
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
        bool: Valid (True) or not (False)
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
        print(f"psw must be a str type, {type(psw)} given.")
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
        bool: Valid salt (True) or not (False)
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

def read_filekey(filekey: str, return_value: bool = False) -> str:
    """Displays or returns the Base64 key of a filekey.

    Args:
        filekey (str): Filekey with extension

        return_value (bool): If True, the 'content'
        variable is returned, otherwise it's simply
        displayed. Default to False. (optional)
    
    Error:
        Invalid filekey : sys.exit(1)    
    
    Return:
        str : The b64 key
    """

    if valid_filekey(filekey):
        with open(filekey, "r") as f:
                content = f.read()
                if not return_value:
                    print(content)
                else:
                    return content
    else:
        sys.exit(1)

def create_filekey(file_name: str, key: str):
    """Creates a filekey based on a base64 key.

    If the key is valid, this filekey can be used to 
    encrypt and decrypt data. 

    Args:
        file_name (str): Desired name for filekey without
        extension

        key (str): Secret key (base64 urlsafe)
    
    Error:
        Invalid file name: sys.exit(1)
        Invalid filekey name: sys.exit(1)
        Invalid key: sys.exit(1)
    """

    if not valid_filename(file_name):
        sys.exit(1)

    if not valid_filekey_name(file_name, create = True):
        sys.exit(1)

    # No spaces
    key = key.replace(' ', '')
    key_bytes = bytes(key, 'ascii')

    if valid_b64_urlsafe(key_bytes):
        with open(file_name + FILEKEY_EXT, 'wb') as f:
            f.write(key_bytes)
        print(f"{file_name + FILEKEY_EXT} has been created in the current folder")
    else:
        print("Invalid key, must be base64 urlsafe")
        sys.exit(1)

def since_when(token_timestamp: int) -> str:
    """Returns the elapsed time between an inserted 
    timestamp and the current one. The function returns 
    the elapsed time by units of time in a readable form.
    Example : "2 days, 1 hour, 22 minutes, 6 seconds"

    The function uses the 'relativedelta' method from 
    'dateutil' module to take into account the variable 
    length of months and years.

    Args:
        token_timestamp (int): The given timestamp
    
    Error:
        Invalid timestamp : ValueError

    Returns:
        str: Text of the elapsed time.
    """

    # Invalid timestamp - Not an int
    if not isinstance(token_timestamp, int):
        raise ValueError("Error: invalid timestamp, must be a positive integer")
    
    # Invalid timestamp - Not a positive int
    if isinstance(token_timestamp, int) and token_timestamp <= 0:
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
    """Prints the timestamp of a Fernet token. 
    Depending on the method used to encrypt the file: 
    with a filekey or with a password.

    Mutually exclusive args:
    If the 'filekey' argument is set, the 'psw' and 'salt' 
    arguments must not be. Conversely, if 'psw' and 
    'salt' are set, 'filekey' must not be.

    Args:
        encrypted_file (str): Encrypted file name present 
        in the current folder

        filekey (str | None): The filekey used to encrypt 
        the file. Defaults to None.

        psw (str | None): The password used to encrypt the 
        file. Defaults to None.

        salt (str | None): The salt used in combination 
        with the password to encrypt the file. 
        Defaults to None.
    
    Error:
        File not found: sys.exit(1)
        Invalid filekey: sys.exit(1)
        Invalid psw: sys.exit(1)
        Invalid salt: sys.exit(1)
        Invalid command combinaison: sys.exit(1)
        Unexpected error: raise Exception
    
    Return:
        int : The Unix timestamp of the token
    """
    if not exists(encrypted_file):
        print(f"{encrypted_file} not found")
        sys.exit(1)
    
    # From a file crypted with a filekey
    if filekey != None and (psw == None and salt == None):
        if not valid_filekey(filekey):
            sys.exit(1)

        with open(filekey, 'rb') as key_file:
            key = key_file.read()
        
        f = Fernet(key)
    
    # From a file crypted with a psw and a salt
    elif (psw != None and salt != None) and filekey == None:
        if valid_password(psw) and valid_salt(salt):
            f = psw_derivation(psw, salt)
        else:
            sys.exit(1)
    
    # ERROR
    else:
        print("Wrong args combinaison, must be :")
        print("encryted_file + filekey OR "
              "encypted_file + psw + salt")
        sys.exit(1)

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
        raise

def salt_gen():
    """Generates a random salt value and print it

    Returns:
        str: The b64-urlsafe salt value
    """    
    salt = urandom(16) # 16 random bytes (128 bits)
    salt_b64 = base64.urlsafe_b64encode(salt).decode('ascii')

    print(salt_b64)

def psw_gen(length=17, include_uppercase=True, 
            include_lowercase=True, include_digits=True, 
            include_symbols=False):
    """Generates and a strong random password and print it.

    The function uses the 'secrets' module to randomly 
    select characters from an iterable (alphabet) in a 
    cryptographically secure way, using system entropy.

    Note : by default, symbol inclusion is disabled, as 
    this could generate syntax conflicts in the terminal.
    To compensate for this, the password length is set to 
    17 by default, in order to keep the entropy above 
    100 bits.

    Args:
        length (int, optional): Password length. Defaults 
        to 17.

        include_uppercase (bool, optional): Inclusion of 
        capital letters. Defaults to True.

        include_lowercase (bool, optional): Inclusion of 
        lowercase letters. Defaults to True.
        
        include_digits (bool, optional): Inclusion of 
        digits. Defaults to True.

        include_symbols (bool, optional): Inclusion of 
        symbols. Defaults to False to avoid syntax conflicts.

    Raises:
        No char type: ValueError
    """

    if length < 12:
        raise ValueError("Password length must be at least 12 characters.")

    alphabet = ""
    if include_uppercase:
        alphabet += ascii_uppercase
    if include_lowercase:
        alphabet += ascii_lowercase
    if include_digits:
        alphabet += digits
    if include_symbols:
        alphabet += punctuation

    # All booleans to False
    if not alphabet:
        raise ValueError("At least one character type must be included.")

    # Loop in which the secrets.choice() method chooses 
    # the desired number of random characters from the 
    # available characters in 'alphabet'
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        # Additional check to ensure that all character 
        # types are present if requested. If not, another 
        # generation is tempted
        if (include_uppercase and not any(c.isupper() for c in password)) or \
            (include_lowercase and not any(c.islower() for c in password)) or \
            (include_digits and not any(c.isdigit() for c in password)) or \
            (include_symbols and not any(c in punctuation for c in password)):
            continue
        # All character types are present
        else:
            break

    print(password)

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

        salt (str | None): Given salt value.
        Defaults to None. (optional)

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

def get_confidential_input(prompt: str) -> str:
    """Retrieves and returns a confidential entry by 
    replacing each inserted character with an asterisk on 
    the terminal display.

    Args:
        prompt (str): 

    Raises:
        Invalid char: KeyboardInterrupt

    Returns:
        str: Plain text input inserted by the user
    """    
    secret_input = ""
    substitution_char = '*'

    sys.stdout.write(prompt) # Writing to std output
    sys.stdout.flush() # Instant display
    
    # OS detection
    # Replacing user input with asterisks means bypassing the 
    # standard echo of characters entered from the keyboard. 
    # To achieve this, we need to use operating system-specific
    # functions for low-level management of terminal 
    # input/output, so as to be able to display asterisks 
    # instead of real characters. We are therefore planning 
    # two separate procedures: one for Windows and another 
    # for Linux.
    if sys.platform == "win32":  # Windows
        import msvcrt
        while True:
            # reads a single character from the keyboard 
            # without echo (without displaying it in the 
            # terminal). The character is returned in bytes.
            char = msvcrt.getch()

            # The enter key is pressed
            if char in {b"\r", b"\n"}:  # Enter key
                break
            
            # The backspace key is pressed. The last char 
            # is deleted
            elif char == b"\x08":
                if len(secret_input) > 0:
                    secret_input = secret_input[:-1]
                    # We replace the last character 
                    # displayed with a space, then go back 
                    # again (\b) to visually delete the 
                    # character.
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            
            # Directional key prefixes on Windows.
            # We make sure that the cursor cannot move 
            # other than by using the backspace key.
            elif char == b"\xe0":  # 
                char = msvcrt.getch()  # Lire le code spécifique de la flèche
                if char == b"H":  # Up
                    pass
                elif char == b"P":  # Down
                    pass
                elif char == b"K":  # Left
                    pass
                elif char == b"M":  # Right
                    pass

            # Ctrl+C / Ctrl+V
            elif char == b"\x03" or char == b'\x16':  # 
                pass
            
            # ECHAP
            elif char == b'\x1b':
                pass
            
            # All other inserted keys are retrieved here, 
            # since not all of them are printable, we attempt 
            # to decode the input in utf-8 in order to handle 
            # any exception appropriately
            else:
                try:
                    secret_input += char.decode("utf-8")
                except UnicodeDecodeError:
                    print("Invalid input")
                    sys.stdout.write(prompt)
                    sys.stdout.flush()
                    continue

                sys.stdout.write(substitution_char)
                sys.stdout.flush()

    else:  # Linux/macOS
        # termios : controls low-level terminal parameters 
        # (specific to Unix-like systems)
        # tty : provides high-level functions to manage 
        # terminal modes, such as "raw" mode (specific to 
        # Unix-like systems)
        import termios
        import tty

        # Retrieves the file descriptor (an integer uniquely 
        # identifying an open file or a data floxw) associated 
        # with standard input (sys.stdin)
        fd = sys.stdin.fileno()

        # Retrieves the terminal's current settings 
        # (associated with the fd file descriptor) and stores 
        # them in the old_settings variable. These settings 
        # will be restored later to restore normal terminal 
        # behavior.
        old_settings = termios.tcgetattr(fd)

        # We create a try...finally block to guarantee that 
        # the terminal parameters will be restored to their 
        # initial state, even if an error occurs during 
        # password entry.
        try:
            # Configure terminal in raw mode, disabling echo 
            # of characters entered and management of special 
            # keys.
            tty.setraw(fd)  # Set raw mode (no echo)
            while True:
                # Reading a character from std input
                char = sys.stdin.read(1)

                # Enter key pressed
                if char in {"\r", "\n"}:
                    break

                # Backspace key pressed. The last char is 
                # deleted.
                elif char == "\x7f":
                    if len(secret_input) > 0:
                        secret_input = secret_input[:-1]
                        sys.stdout.write("\b \b")  # Remove asterisk
                        sys.stdout.flush()
                
                # Directionnal keys pressed
                elif char == "\x1b":
                    next1, next2 = sys.stdin.read(1), sys.stdin.read(1)
                    if next1 == "[":
                        if next2 == "A":  # Up
                            pass
                        elif next2 == "B":  # Down
                            pass
                        elif next2 == "C":  # Right
                            pass
                        elif next2 == "D":  # Left
                            pass

                # Ctrl+C
                elif char == "\x03" or char == "\x16":
                    pass

                # All other keyboard inputs
                else:
                    # The inserted character is added
                    secret_input += char

                    # Displays the substitution character on 
                    # the standard output
                    sys.stdout.write(substitution_char)
                    sys.stdout.flush()
        finally:
            # Restores initial terminal settings (those stored 
            # in old_settings) using file descriptor fd. 
            # termios.TCSADRAIN indicates that changes should 
            # be applied after all pending output has been 
            # written.
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)  # Restore initial params

    sys.stdout.write("\n")  # Go to next line
    return secret_input

def encrypt(filename: str, overwrite: bool = True, 
            given_filekey: Union[str, None] = None, 
            psw: Union[str, None] = None, 
            salt: Union[str, None] = None):
    """Encrypts a file in 3 different ways :

    1. By generating a random filekey in the current 
    folder
    2. By retrieving a filekey already present in the 
    current folder
    3. By taking a password and a salt

    These 3 methods are mutually exclusive.

    Args:
        filename (str): File name to encrypt.

        overwrite (bool): Overwrite the file to
        encrypt. Defaults to True. (optional)

        given_filekey (str | None): Name of the filekey 
        already present in the current folder for 
        encrypting with. Defaults to None.

        psw (str | None): Password to encrypt the file.
        Defaults to None.

        salt (str | None): Custom salt given to encrypt
        the file. Defaults to None.

    Error:
        File not found: sys.exit(1)
        Invalid filekey: sys.exit(1)
        Invalid password: sys.exit(1)
        Invalid salt: sys.exit(1)
        Unexpected error: sys.exit(1)
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
                sys.exit(1)

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
            sys.exit(1)

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
                    sys.exit(0)
                
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
                sys.exit(1)
        
        # A salt has been inserted, the password and salt 
        # must be verified.
        elif salt != None:
            if valid_password(psw) and valid_salt(salt):
                f = psw_derivation(psw, salt)
            else:
                sys.exit(1)

        # Who knows ?
        else:
            print("Unexpected error ('encrypt' with psw)")
            sys.exit(1)

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
            sys.exit(1)
        
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
        sys.exit(1)

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
            salt: Union[str, None] = None):
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

    Error:
        File not found: sys.exit(1)
        Invalid filekey: sys.exit(1)
        Invalid psw: sys.exit(1)
        Invalid salt: sys.exit(1)
        Invalid token: sys.exit(1)
    """
    print(f"---- Decryption of {filename} ----")

    # No password given : function will be dealing with a filekey
    if psw == None:
        if not valid_filekey(filekey_name):
            sys.exit(1)

        # Filekey reading and retrieved as bytes
        print(f"Filekey reading ({filekey_name})...")
        try:
            with open(filekey_name, 'rb') as filekey:
                key = filekey.read() # key = bytes
        except FileNotFoundError:
            print(f"Error : No such filekey : '{filekey_name}'"
            " in the current folder")
            sys.exit(1)

        # Fernet object creation with key
        f = Fernet(key)

    # Password given : function will be dealing without a filekey
    else:
        if valid_password(psw) and valid_salt(salt):
            f = psw_derivation(psw, salt)
        else:
            sys.exit(1)

    # Recovery the file to be decrypted (bytes)
    print(f"{filename} reading...")
    try:
        with open(filename, 'rb') as encrypted_file:
            encrypted = encrypted_file.read() # encrypted = bytes
    except FileNotFoundError:
        print(f"Error : No such file : '{filename}' in the current folder")
        sys.exit(1)

    # File data decryption
    print("Decrypting data...")
    try :
        decrypted = f.decrypt(encrypted)
    except InvalidToken:
        print("Error : Invalid Fernet token")
        sys.exit(1)

    # Overwriting the file with decrypted bytes data
    # File regains its integrity
    print(f"{filename} writing...")
    with open(filename, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

    print(f"---- Operation completed successfully ----")

def main():
    """The argparse structure is defined, as are its call
    logics

    Error:
        Invalid command: sys.exit(1)
        Wrong command combinaison: sys.exit(1)
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

    # - - - - - - Command : salt
    parser_salt = subparsers.add_parser(
        "salt",
        help="Generates a random salt value"
    )

    # - - - - - - Command : psw
    parser_psw = subparsers.add_parser(
        "psw",
        help="Generates a strong random password"
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
        help="Filekey name used to encrypt the file",
        default= None
    )
    parser_timestamp.add_argument(
        "-p", "--password",
        help="Password used to encrypt the file",
        default= None, action= "store_true"
    )

    # - - - - - - Command : create
    parser_create = subparsers.add_parser(
        "create",
        help="Create a new keyfile with a given key"
    )
    parser_create.add_argument(
        "filename",
        help="File name (without its extension)"
    )

    # - - - - - - Command : clean
    parser_clean = subparsers.add_parser(
        "clean", help="Cleans the clipboard"
    )

    # - - - - - - Command : encrypt
    parser_encrypt = subparsers.add_parser("encrypt",
        help= "Encrypts a file")
    parser_encrypt.add_argument("filename",
        help= "File name to be encrypted (with its extension)")
    parser_encrypt.add_argument("-f", "--filekey",
        help= "Name of the existing filekey (with its extension)", default=None)
    parser_encrypt.add_argument("-p", "--password", default= None,
        help= "Encrypts with a given password", action="store_true")
    parser_encrypt.add_argument("-s", "--salt", default= None,
        help= "Encrypts with a given salt value", action="store_true")

    # The -overwrite and -copy options are mutually
    # exclusive, only one of them can be called.
    # Choosing either option is mandatory
    group_encrypt = parser_encrypt.add_mutually_exclusive_group(required=True)
    group_encrypt.add_argument("-ow", "--overwrite",
        action="store_true", help= "Overwrites the file")
    group_encrypt.add_argument("-c", "--copy",
        action="store_true", help= "Copy the file "
        "before overwriting it in its encrypted version")

    # - - - - - - Command : decrypt
    parser_decrypt = subparsers.add_parser("decrypt",
        help= "Decrypts a file")
    parser_decrypt.add_argument("filename",
        help= "File name to decrypt (with its extension)")
    parser_decrypt.add_argument("filekey", nargs="?",
        help= "The filekey containing the secret key for"
        " decrypting the file (with its extension)."
        " If decryption is to be done using a password, "
        "this field does not need to be filled in.")
    parser_decrypt.add_argument("-p", "--password", 
        default= None, help= "Decrypts with a given password", 
        action="store_true")
    parser_decrypt.add_argument("-s", "--salt", default= None,
        help= "Decrypts with a given salt value", action="store_true")

    # - - - - - - Call logics - - - - - -
    args = parser.parse_args()

    if args.command == "install":
        install_from_requirements()
    
    elif args.command == "salt":
        salt_gen()
    
    elif args.command == "psw":
        psw_gen()

    elif args.command == "read":
        read_filekey(args.filekey)
    
    elif args.command == "timestamp":
        password = None
        salt = None

        # Conflict
        if (args.filekey and args.password):
            print("ERROR : You must provide either a 'filekey' or a "
                "'--password'.")
            sys.exit(1)

        # File encrypted with a filekey
        if args.filekey:
            get_timestamp(
            encrypted_file=args.encrypted_file,
            filekey= args.filekey, psw= password,
            salt= salt)
        
        # File encrypted with a psw and a salt
        elif args.password:
            password = get_confidential_input("Password: ")
            salt = get_confidential_input("Salt: ")

            get_timestamp(
            encrypted_file=args.encrypted_file,
            filekey= args.filekey, psw= password,
            salt= salt)
        
        else:
            print("Wrong command combinaison")
            sys.exit(1)

    elif args.command == "create":
        key = get_confidential_input("Key: ")
        create_filekey(args.filename, key)
    
    elif args.command == "clean":
        clean()

    elif args.command == "encrypt":
        password = None
        salt = None

        if (args.password and args.filekey):
            print("ERROR : You must provide either a 'filekey' or a "
                "'--password'.")
            sys.exit(1)

        if args.password and not args.salt:
            password = get_confidential_input("Password: ")
            salt = None
        
        if args.password and args.salt:
            password = get_confidential_input("Password: ")
            salt = get_confidential_input("Salt: ")

        if args.overwrite and not args.copy:
            encrypt(args.filename, overwrite=True, 
                    given_filekey=args.filekey, 
                    psw=password, salt=salt)

        if args.copy and not args.overwrite:
            encrypt(args.filename, overwrite=False, 
                    given_filekey=args.filekey, 
                    psw=password, salt=salt)

    elif args.command == "decrypt":
        password = None
        salt = None
        # Wrong command
        if (args.password is None and args.filekey is None) or (args.password and args.filekey):
            print("ERROR : You must provide either a 'filekey' or a "
                "'--password'.")
            sys.exit(1)

        # File must be decrypted with a password
        elif args.password:
            password = get_confidential_input("Password: ")
            salt = get_confidential_input("Salt: ")
    
            decrypt(args.filename, psw=password, 
                        salt=salt)

        # File must be decrypted with a filekey
        else:
            decrypt(args.filename, args.filekey)

    else:
        print("ERROR : Unknown argument")
        sys.exit(1)

if __name__ == "__main__":
    main()