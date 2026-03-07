""" 
Filecrypt encrypts/decrypts files in the current folder 
using the AES algorithm via the Fernet implementation.

To do this, simply :
- Place this script in the folder containing the file(s) 
to be encrypted or decrypted.
- Go to this folder from the terminal.
- Call the script: 'python filecrypt.py' followed by the
desired command.

Example : 'python filecrypt.py encrypt image.jpg -ow'

All information and examples on :
https://github.com/Kartmaan/filecrypt

Or :
'python filecrypt.py --help'

Author : Kartmaan
Date : 2026-03-07
Version : 1.2.0
"""

# ===================================================================
#                            BUILT-IN MODULES
# ===================================================================
import argparse
import base64
import errno
import getpass
from datetime import datetime as dt
from os import chmod, remove, rmdir, urandom, walk
from os.path import abspath, basename, dirname, exists, getsize
from os.path import isdir, isfile, join, relpath, realpath
import secrets
from shutil import copyfile, rmtree
import stat
from string import ascii_letters, ascii_lowercase
from string import ascii_uppercase, digits, punctuation
import subprocess
import sys
from typing import Union
from zipfile import ZipFile, BadZipFile, ZIP_DEFLATED

# ===================================================================
#                             CONSTANTS
# ===================================================================
USER_OS = sys.platform
SUPPORTED_OS = ["win32", "linux", "darwin"]
SAFE_MODE = False
SCRIPT_PATH = abspath(sys.argv[0])
SCRIPT_DIR = dirname(SCRIPT_PATH)
SCRIPT_NAME = basename(SCRIPT_PATH)
REQUIREMENTS = ["cryptography", "pyperclip", "python-dateutil"]
FILEKEY_EXT = ".key"

# ===================================================================
#                        NON-BUILT-IN MODULES
# ===================================================================
def install_from_requirements():
    """
    Installs modules listed in the 'REQUIREMENTS' list with pip.
    """
    for package in REQUIREMENTS:
        try:
            # Tries to install the package with pip
            print(f"Checking and installing the package : {package}.")
            subprocess.check_call([sys.executable, "-m",
                "pip", "install", package])
            print(f"{package} has been successfully installed.")

        except subprocess.CalledProcessError:
            print(f"Error: Unable to install {package}. Check your connection.")
            raise

        except Exception as e:
            print(f"An unexpected error has occurred : {e}.")
            raise

# As these modules are not built-in, we insert them in a 
# try...except block to suggest that the user install 
# them if they are not present in his environment.
try :
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from dateutil.relativedelta import relativedelta
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
            print("Invalid input.")
            continue

# ===================================================================
#                          SAFETY CHECKS
# ===================================================================
def safety_check(func):
    """Decorator : prevents a function from operating in 
    SAFE_MODE.

    The decorator is attached to all functions able of 
    modifying/deleting files/folders.

    Args:
        func: The decorated function.

    Returns:
        func: SAFE_MODE OFF -> The function is called
        wrap: SAFE_MODE ON -> The function is muted
    """    
    txt=f"This functionality ({func.__name__}) isn't available in safe mode."
    def wrap(*args, **kwargs):
        if SAFE_MODE:
            print(txt)
            sys.exit(1)
        else:
            return func(*args, **kwargs)
    return wrap

def in_danger_zone(path: str) -> bool:
    """Determines whether a path corresponds to a 
    sensitive area of the system.

    Args:
        path (str): Path to check.

    Returns:
        bool: True if the path corresponds to a sensitive 
        area. False otherwise.
    """
    # For each system, all paths STARTING with these are 
    # considered sensitive    
    danger_roots = {
    "win32": ["c:\\windows"],
    "linux": ["/bin", "/sbin", "/usr", "/etc", "/var"],
    "darwin": ["/bin", "/sbin", "/usr", "/etc", "/var", 
               "/System"]}

    # For each system, all paths EQUAL to these are 
    # considered sensitive
    danger_path = {
    "win32": ["c:\\"],
    "linux": ["/"],
    "darwin": ["/"]}

    # Resolve symlinks and normalize the path, then convert to lowercase
    resolved_path = realpath(path).lower()

    for root_path in danger_roots[USER_OS]:
        if resolved_path.startswith(root_path):
            return True
        
    for root_path in danger_path[USER_OS]:
        if resolved_path == root_path:
            return True
        
    return False

def in_current_folder(path: str) -> bool:
    """Checks if the path or file name inserted by the 
    user is in the script's current folder.

    Functions that modify file contents or delete 
    them, expect a target path as argument, and it's 
    important to ensure that these functions CAN'T reach 
    sensitive areas of the system.

    The script goes into SAFE_MODE when it is in a 
    sensitive area of the system, which prevents the 
    script's modifier functions from being called. 
    However, to ensure that these zones cannot be reached 
    when the script is not in SAFE_MODE, by, for example, 
    entering a sensitive path as an argument, these are 
    checked to ensure that they are actually in the 
    script's current folder.

    Args:
        path (str): Path to check.

    Returns:
        bool: True if the path is in the current folder.
        False otherwise.
    """
    # Resolve symlinks and normalize the path, then convert to lowercase
    real_target_path = realpath(path).lower()
    real_script_dir = realpath(SCRIPT_DIR).lower()

    if real_target_path.startswith(real_script_dir):
        return True
    else:
        return False

def handle_remove_readonly(func: callable, path: str, exc: tuple[any, Exception, any]) -> None:
    """Handles errors in deleting read-only files or folders, particularly under Windows.

    This function is designed to be used as a callback via the 'onerror' parameter of shutil.rmtree(). 
    It intercepts deletion failures due to insufficient permissions (EACCES), modifies the element's 
    attributes to allow writing, and then retries the operation.

    Args:
        func: The function that failed.
        path: The absolute or relative path of the file or folder to be deleted.
        exc: A tuple containing information about the exception thrown (type, value, traceback), 
        as returned by sys.exc_info().
    
    Raises:
        Exception: Re-throws the original exception if the error is not related to an access 
        problem (EACCES) or if the rights modification fails.
    """
    excvalue = exc[1]
    if func in (rmdir, remove) and excvalue.errno == errno.EACCES:
        chmod(path, stat.S_IWRITE) # We make the file/folder writable
        func(path) # We'll try the deletion again.
    else:
        raise

# ===================================================================
#                          INITIAL CHECKS
# ===================================================================

if USER_OS not in SUPPORTED_OS:
    print(f"This OS ({USER_OS}) isn't supported by the script")
    print(f"Supported OS: {SUPPORTED_OS}")
    sys.exit(1)

# If the script is in a sensitive area of the system, 
# SAFE_MODE is activated.
if in_danger_zone(SCRIPT_PATH):
    SAFE_MODE = True
    print("- - - - CAUTION - - - -") 
    print("SAFE MODE: The script is located in a critical area of the " 
          "system, some functions will be disabled.")
    print("")

# ===================================================================
#                      INPUT CONTROL FUNCTIONS
# ===================================================================
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
        print("File name must be a str.")
        return False

    # The string is too long
    if len(file_name) > 255:
        print("File name is too long (must contain less "
              "than 256 characters).")
        return False

    # Iteration to search for a character not in the
    # whitelist
    for char in file_name:
        if char not in whitelist:
            print("Invalid char in file name.")
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
        " given.)")
        return False

    # - The filekey will be recovered -
    # We are looking for a filekey that is supposed to be
    # already present in the current folder. We make sure
    # the file exists and has the right extension
    if not create:
        if not exists(filekey):
            print(f"{filekey} not found.")
            return False

        if not filekey.endswith(FILEKEY_EXT):
            print(f"Filekey must be '{FILEKEY_EXT}'.")
            return False

    # - The filekey will be created -
    # We make sure no file with the same name exists
    else:
        if not valid_filename(filekey):
            return False
        
        if exists(filekey + FILEKEY_EXT):
            print(f"{filekey} already exists.")
            return False

    return True

def valid_filekey_key(filekey: str) -> bool:
    """Checks whether the key present in a filekey is valid.

    A valid Fernet key must be exactly 32 url-safe base64-encoded
    bytes. Checking only that the content is valid base64 is not
    sufficient: a string can be decodable yet produce a byte sequence
    of the wrong length, causing Fernet() to raise a silent ValueError.

    Args:
        filekey (str): Given filekey

    Returns:
        bool: Valid key (True) or not (False).
    """
    with open(filekey, "r") as f:
        content = f.read().strip()

    # Step 1 — must be valid urlsafe base64
    if not valid_b64_urlsafe(content):
        print("Invalid key format: not a valid base64 urlsafe string.")
        return False

    # Step 2 — decoded bytes must be exactly 32 (Fernet requirement)
    import base64 as _b64
    decoded = _b64.urlsafe_b64decode(content)
    if len(decoded) != 32:
        print(f"Invalid key length: expected 32 bytes, got {len(decoded)}.")
        return False

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
              "characters long.")
        return False
    
    for char in psw:
        if char in blacklist:
            return False

    return True

def get_confidential_input(prompt: str) -> str:
    """Gets confidential input from the user without echoing to the terminal.

    This function is a wrapper around `getpass.getpass()`, providing a
    standard way to prompt the user for sensitive information like passwords.
    The input is not displayed on the screen as the user types.

    Args:
        prompt: The message to display to the user before input.

    Returns:
        str: The user's input.
    """
    return getpass.getpass(prompt)

# ===================================================================
#                          FEATURE FUNCTIONS
# ===================================================================
def _clean_linux_native() -> bool:
    """Attempts to clear the clipboard on Linux using native 
    tools (xclip, xsel, wl-clipboard), without requiring pyperclip.

    Tries each tool silently via subprocess. Stops and returns 
    True as soon as one succeeds.

    Returns:
        bool: True if a native tool successfully cleared the 
        clipboard, False if none were available.
    """
    # Each entry: (command, description)
    # We pipe an empty string into each tool to clear the clipboard.
    native_commands = [
        ["xclip", "-selection", "clipboard"], # X11
        ["xsel", "--clipboard", "--clear"], # X11
        ["wl-copy", "--clear"], # Wayland
    ]

    for cmd in native_commands:
        try:
            result = subprocess.run(
                cmd,
                input=b"",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            # Tool not installed, try the next one
            continue

    return False

def clean():
    """Clears confidential data on the clipboard.

    On all platforms, pyperclip is tried first. On Linux, if 
    pyperclip raises PyperclipException (no copy/paste mechanism 
    found), native clipboard tools are attempted as a fallback 
    (xclip, xsel, wl-clipboard) — without requiring any 
    installation. If none are available either, the user is 
    informed of the situation and of the available options.
    """
    try:
        pyperclip.copy("")
        print("The clipboard has been erased.")

    except pyperclip.PyperclipException:
        # pyperclip has no mechanism available — try native Linux tools
        if USER_OS == "linux":
            if _clean_linux_native():
                print("The clipboard has been erased.")
            else:
                # Nothing worked: inform the user clearly
                _clipboard_no_mechanism_msg()
                print("")
                print("Alternatively, you can clear the clipboard manually")
                print("by copying any innocuous text (e.g. a space).")
        else:
            # Non-Linux system: re-raise, this is unexpected
            raise

def _copy_linux_native(text: str) -> bool:
    """Attempts to copy text to the clipboard on Linux using native
    tools (xclip, xsel, wl-clipboard), without requiring pyperclip.

    Mirrors _clean_linux_native() but pipes the given text instead
    of an empty string, covering both X11 and Wayland environments.

    Args:
        text (str): The text to copy to the clipboard.

    Returns:
        bool: True if a native tool successfully copied the text,
        False if none were available.
    """
    native_commands = [
        ["xclip", "-selection", "clipboard"], # X11
        ["xsel",  "--clipboard", "--input"],   # X11
        ["wl-copy"],                           # Wayland
    ]

    for cmd in native_commands:
        try:
            result = subprocess.run(
                cmd,
                input=text.encode(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            # Tool not installed, try the next one
            continue

    return False

def _clipboard_no_mechanism_msg() -> None:
    """Prints a standardised message when no clipboard mechanism
    is available on the current Linux system.

    Factored out to keep copy_filekey() and clean() DRY.
    """
    print("Unable to access the clipboard automatically.")
    print("No clipboard utility was found on this system.")
    print("")
    print("You can install one of the following tools:")
    print("  X11     : sudo apt-get install xclip")
    print("            sudo apt-get install xsel")
    print("  Wayland : sudo apt-get install wl-clipboard")

def copy_filekey(filekey: str):
    """Copies the Base64 key stored in a filekey to the clipboard.

    On all platforms, pyperclip is tried first. On Linux, if
    pyperclip raises PyperclipException (no copy/paste mechanism
    found), native clipboard tools are attempted as a fallback
    (xclip, xsel, wl-clipboard) — without requiring any
    installation. If none are available either, the user is
    informed of the situation and of the available options.

    Args:
        filekey (str): Filekey name (with extension).

    Error:
        Invalid filekey : sys.exit(1)
        No clipboard mechanism available : informs the user
    """
    key = read_filekey(filekey, return_value=True)

    if key is None:
        sys.exit(1)

    try:
        pyperclip.copy(key)
        print("Key copied to clipboard.")
        print("Don't forget to clean the clipboard after use "
              "('clean' command).")

    except pyperclip.PyperclipException:
        if USER_OS == "linux":
            if _copy_linux_native(key):
                print("Key copied to clipboard.")
                print("Don't forget to clean the clipboard after use "
                      "('clean' command).")
            else:
                _clipboard_no_mechanism_msg()
        else:
            raise

def read_filekey(filekey: str, return_value: bool = False) -> str | None:
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

@safety_check
def create_filekey(file_name: str, key: str):
    """Creates a filekey based on a base64 key.

    If the key is valid, this filekey can be used to 
    encrypt and decrypt data. 

    Args:
        file_name (str): Desired name for filekey without extension
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
        print(f"{file_name + FILEKEY_EXT} has been created in the current folder.")
    else:
        print("Invalid key, must be base64 urlsafe.")
        sys.exit(1)

@safety_check
def secure_delete(filename: str, encryption_passes: int = 2,
                  shuffle: bool = False, silent_mode: bool = False):
    """
    Securely deletes files/folders from the current folder.

    Before deletion, files are blindly encrypted 
    several times (without the key being communicated) 
    with a new random key for each pass. Finally, the 
    file size is truncated to coincide with the original 
    size.
    
    Optionally, the file bytes can be randomly shuffled 
    just after truncation by activating the option 
    '--shuffle' / '-s'.

    Note about encryption passes: The file size can 
    temporarily increase significantly with each 
    encryption pass. Even if the file returns to its 
    initial size after the truncation phase, setting 
    the number of passes to 2 seems a more than 
    acceptable compromise, particularly for large files.

    Note about the shuffle option: The operation can 
    be long for large files (approx. 2 min on a standard 
    PC for a 100MB file).

    Args:
        filename (str): The file name to delete.

        encryption_passes (int): The number of encryption 
        passes. Default to 2.

        shuffle (bool): Random file bytes shuffling 
        before deletion. Default to False.

        silent_mode (bool): Minimum prints
    
    Error:
        Invalid filename arg: sys.exit(1)
        Invalid encryption_passes arg: sys.exit(1)
        File not found: sys.exit(1)
        Current script as filename arg: sys.exit(1)
        Error during encryption: raise Exception
        Error during shuffle: OSError
    """
    is_filekey = False
    is_folder = False

    if not isinstance(filename, str):
        print("filename must be a str.")
        sys.exit(1)
    
    elif not isinstance(encryption_passes, int) or encryption_passes < 0:
        print("Invalid 'encryption_passes' arg. Must be an integer >= 0.")
        sys.exit(1)
    
    elif not in_current_folder(filename):
        print(f"{filename} not in the current folder.")
        sys.exit(1)
    
    # Prevents script from killing itself 
    elif filename == SCRIPT_PATH or filename == SCRIPT_NAME:
        print("The script cannot delete itself.")
        sys.exit(1)

    # Early folder detection (before confirmation)
    if isdir(filename):
        is_folder = True
    # The file to be deleted is a filekey
    elif filename.endswith(FILEKEY_EXT):
        is_filekey = True

    if not silent_mode:
        # User confirmation — single prompt, adapted to the target type
        choice = None
        while choice != "y" and choice != "n":
            if is_folder:
                # Count all files in the folder (recursively)
                file_count = sum(len(files) for _, _, files in walk(filename))
                print(f"You are about to irreversibly delete the "
                      f"folder '{filename}' and all its contents.")
                print(f"From: {abspath(filename)}")
                print(f"Files to delete: {file_count}")
            elif is_filekey:
                print("You are about to irreversibly delete the " 
                    f"filekey '{filename}', if it's still "
                    "useful for decrypting a file, please "
                    "note its key in a safe place before "
                    "deleting it ('read' command).")
                print(f"From: {abspath(filename)}")
            else:
                original_file_size = getsize(filename)
                print("You are about to irreversibly delete " 
                    f"the file '{filename}'.")
                print(f"From: {abspath(filename)}")
                print(f"File size: {round(original_file_size/1024, 3)} ko")

            choice = input("Do you confirm this operation? (y/n): ")
            choice = choice.lower()

            if choice == "y":
                pass
            elif choice == "n":
                print("Exiting...")
                sys.exit(0)
            else:
                print("Invalid input.")
                continue

    # Get original file size (only needed for files, after confirmation)
    if not is_folder:
        original_file_size = getsize(filename)

    # TARGET IS A FOLDER
    if is_folder:
        if not silent_mode:
            print(f"Processing folder '{filename}'...")

        # Securely delete each file inside the folder recursively
        for root, dirs, files in walk(filename):
            for file in files:
                file_path = join(root, file)
                secure_delete(file_path, encryption_passes, shuffle, silent_mode=True)
        
        # Once empty, remove the folder tree
        try:
            rmtree(filename, onerror=handle_remove_readonly)
            if not silent_mode:
                print(f"Folder '{filename}' has been deleted.")
        except Exception as e:
            print(f"Error removing folder '{filename}': {e}")
        
        return  # End of function for folder case
    
    if not silent_mode:
        if encryption_passes > 0:
            print("Encryption...")

    # Encryption passes
    for i in range(encryption_passes):
        # Generate a random key
        key = Fernet.generate_key()

        # Generate a random salt 
        salt = urandom(16)

        # Derive the key using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        derived_key = kdf.derive(key)
        encoded_key = base64.urlsafe_b64encode(derived_key)

        f = Fernet(encoded_key)

        try:
            with open(filename, "rb") as file:
                original_data = file.read()

            encrypted_data = f.encrypt(original_data)

            with open(filename, "wb") as file:
                file.write(encrypted_data)

            if encryption_passes > 1 and not silent_mode:
                print(f"Pass {i + 1}/{encryption_passes} completed.")
        except Exception as e:
            print(f"Error during encryption pass {i + 1}: {e}.")
            raise

    # File truncation and shuffle
    # File is truncated and bytes are randomly shuffled if
    # 'shuffle' is True.
    try:
        with open(filename, "r+b") as f:
            # Truncates the file to its original size
            if not silent_mode:
                print("Resizing...")
            f.truncate(original_file_size)

            if shuffle:
                if not silent_mode:
                    print("Shuffling...")
                # Bytes type is immutable, so we transform
                # it into a bytearray, which is a mutable 
                # sequence.
                bytes_array = bytearray(f.read())

                # Inplace bytearray shuffle
                # The SystemRandom class uses the operating 
                # system's entropy to make a crypto secure
                # shuffle.
                secrets.SystemRandom().shuffle(bytes_array)

                # returns the cursor to the beginning of the 
                # file before writing the shuffled bytes
                f.seek(0)

                # Writing shuffled bytes
                f.write(bytes_array)
    except OSError:
        raise

    remove(filename)  # Delete the file after encryption
    if not silent_mode:
        print(f"'{filename}' has been deleted.")

@safety_check
def zip_files(targets: list, delete: bool = False):
    """
    Compresses files or folders into a ZIP archive.

    Args:
        zip_files (list): List of targets
        delete (bool): Delete the original files after creating the zip archive.
    """
    # Preliminary check of all files
    for target in targets:
        if not in_current_folder(target):
            print(f"{target} not in the current folder.")
            sys.exit(1)
        if target == SCRIPT_PATH or target == SCRIPT_NAME:
            print("The script cannot zip itself.")
            sys.exit(1)

    zip_filename = "archive.zip"

    # If archive.zip already exist, we request a new name
    if exists(zip_filename):
        print(f"'{zip_filename}' already exists.")
        while True:
            # Naming without extension
            custom_name = input("Enter a name for the archive (without extension): ").strip()
            
            if not custom_name:
                print("Name cannot be empty.")
                continue
            
            zip_filename = custom_name + ".zip"
            
            # We're also checking if this new name is available.
            if exists(zip_filename):
                print(f"'{zip_filename}' also exists. Please choose another name.")
            else:
                break

    # User confirmation for deletion
    if delete:
        print("Compression will delete the following targets:")
        for target in targets:
            print(f"- {target}")
        
        choice = input("Do you confirm the operation ? (y/n): ").lower()
        if choice != 'y':
            print("Cancellation...")
            sys.exit(0)

    print("Zipping...")
    with ZipFile(zip_filename, 'w', ZIP_DEFLATED) as zipf:
        for target_to_zip in targets:
            # Targer is a folder
            if isdir(target_to_zip):
                for root, dirs, files in walk(target_to_zip):
                    for file in files:
                        file_path = join(root, file)
                        arch_name = join(basename(target_to_zip), relpath(file_path, start=target_to_zip))
                        zipf.write(file_path, arcname=arch_name)
                        print(f"Added: {file_path}")
                
                if delete:
                    # Recursive deletion logic
                    total_files = sum([len(files) for r, d, files in walk(target_to_zip)])
                    print(f"Deleting files in {target_to_zip}...")
                    deleted_files = 0
                    for root, dirs, files in walk(target_to_zip):
                        for file in files:
                            secure_delete(join(root, file), silent_mode=True)
                            deleted_files += 1
                            print(f"File deletion {deleted_files}/{total_files}")
                    
                    # Once the files are deleted, the empty folder is deleted. 
                    # We use `onerror` to handle stubborn cases in Windows.
                    try:
                        rmtree(target_to_zip, ignore_errors=False, onerror=handle_remove_readonly)
                        print(f"Folder {target_to_zip} removed.")
                    except Exception as e:
                        print(f"Could not remove folder {target_to_zip}: {e}")

            # Target is a file
            elif isfile(target_to_zip):
                zipf.write(target_to_zip, arcname=basename(target_to_zip))
                print(f"Added : {target_to_zip}")
                
                if delete:
                    secure_delete(target_to_zip, silent_mode=True)
            
            else:
                print(f"Skipping {target_to_zip}: neither a file nor a folder.")

    print(f"'{zip_filename}' created successfully.")
            
@safety_check
def unzip_file(arch_name: str):
    """
    Unzip a zip archive.

    Args:
        arch_name (str): Name of the compressed file
    """
    
    if not in_current_folder(arch_name):
        print(f"{arch_name} not in the current folder.")
        sys.exit(1)
    
    try:
        with ZipFile(arch_name, 'r') as zipf:
            print(f"Unzipping {arch_name}...")
            zipf.extractall()
        print(f"{arch_name} extracted successfully.")
    except FileNotFoundError as e:
        print(f"Error : Archive not found : {e}")
        sys.exit(1)
    except BadZipFile:
        print("Invalid archive. If the archive is encrypted, "
              "please decrypt it first.")
        sys.exit(1)
    except OSError as e:
        print(f"Error during the extraction : {e}")
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
                  psw: Union[str, None] = None) -> None:
    """Prints the timestamp of a Fernet token.
    Depending on the method used to encrypt the file:
    with a filekey or with a password.

    In password mode, the salt is read automatically from the first
    16 bytes of the encrypted file (where it is embedded at
    encryption time) — the user does not need to provide it.

    Mutually exclusive args:
    If 'filekey' is set, 'psw' must not be, and vice versa.

    Args:
        encrypted_file (str): Encrypted file name present 
        in the current folder.

        filekey (str | None): The filekey used to encrypt 
        the file. Defaults to None.

        psw (str | None): The password used to encrypt the 
        file. Defaults to None.

    Error:
        File not found           : sys.exit(1)
        Invalid filekey          : sys.exit(1)
        Invalid psw              : sys.exit(1)
        Bad args combination     : sys.exit(1)
        Unexpected error         : raise Exception
    
    Return:
        int : The Unix timestamp of the token
    """
    if not exists(encrypted_file):
        print(f"{encrypted_file} not found.")
        sys.exit(1)
    
    # From a file encrypted with a filekey
    if filekey is not None and psw is None:
        if not valid_filekey(filekey):
            sys.exit(1)

        with open(filekey, 'rb') as key_file:
            key = key_file.read()
        
        f = Fernet(key)

        with open(encrypted_file, 'rb') as encrypted_data:
            token = encrypted_data.read()
    
    # From a file encrypted with a password
    # Salt is read automatically from the first 16 bytes of the file
    elif psw is not None and filekey is None:
        if not valid_password(psw):
            sys.exit(1)

        with open(encrypted_file, 'rb') as ef:
            raw = ef.read()

        salt_bytes = raw[:16]
        token = raw[16:]

        if len(salt_bytes) < 16:
            print("Error: file too short to contain an embedded salt.")
            sys.exit(1)

        f, _ = psw_derivation(psw, salt_bytes)

    # ERROR
    else:
        print("Wrong args combination, must be :")
        print("encrypted_file + filekey OR encrypted_file + --password.")
        sys.exit(1)

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

def psw_gen(length=17, include_uppercase=True,
            include_lowercase=True, include_digits=True, 
            include_symbols=True, copy_secret: bool = False):
    """Generates and a strong random password and print it.

    The function uses the 'secrets' module to randomly 
    select characters from an iterable (alphabet) in a 
    cryptographically secure way, using system entropy.

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


        copy_secret (bool): If True, copies the generated
        password to the clipboard using the pyperclip ->
        native Linux cascade. Defaults to False.
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
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
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

    if copy_secret:
        try:
            pyperclip.copy(password)
            print("Password copied to clipboard.")
            print("Don't forget to clean the clipboard after use "
                  "('clean' command).")
        except pyperclip.PyperclipException:
            if USER_OS == "linux":
                if _copy_linux_native(password):
                    print("Password copied to clipboard.")
                    print("Don't forget to clean the clipboard after use "
                          "('clean' command).")
                else:
                    _clipboard_no_mechanism_msg()
            else:
                raise

def psw_derivation(psw: str,
                   salt_bytes: Union[bytes, None] = None) -> tuple:
    """Creates a Fernet object from a password and a raw salt.

    The salt is always handled as raw bytes (16 bytes / 128 bits).
    It is no longer displayed or communicated to the user: it is
    embedded directly into the encrypted file by the caller.

    If no salt is provided, a cryptographically secure random salt
    is generated via os.urandom(16).

    Args:
        psw (str): Password to derive the key from.

        salt_bytes (bytes | None): Raw 16-byte salt. If None, a
        random salt is generated. Defaults to None.

    Return:
        tuple[Fernet, bytes]: Fernet object ready to
        encrypt/decrypt, and the raw salt bytes used.
    """
    # The password must be handled in binary form.
    psw = psw.encode('ascii')

    # No salt provided: generate a cryptographically secure one
    if salt_bytes is None:
        salt_bytes = urandom(16) # 16 random bytes (128 bits)

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
        salt = salt_bytes,
        iterations = 480000,
        )

    # The password is derived and combined with the 
    # previously specified parameters. The key is 
    # converted to b64 urlsafe to comply with Fernet 
    # standards
    key = base64.urlsafe_b64encode(kdf.derive(psw))
    f = Fernet(key)

    return f, salt_bytes

@safety_check
def encrypt(filename: str, overwrite: bool = True, 
            given_filekey: Union[str, None] = None, 
            psw: Union[str, None] = None,
            copy_secret: bool = False):
    """Encrypts a file in 3 different ways :

    1. By generating a random filekey in the current folder
    2. By using a filekey already present in the current folder
    3. By taking a password (salt is generated and embedded automatically)

    These 3 methods are mutually exclusive.

    In password mode, a random 16-byte salt is generated at encryption
    time and written as a plain prefix to the encrypted file:
        [16 salt bytes] + [Fernet token]
    The salt is public and does not need to be communicated separately.
    It is recovered automatically at decryption time.

    Args:
        filename (str): File name to encrypt.

        overwrite (bool): Overwrite the file to encrypt.
        Defaults to True. (optional)

        given_filekey (str | None): Name of an existing filekey in
        the current folder to encrypt with. Defaults to None.

        psw (str | None): Password to encrypt the file.
        Defaults to None.

        copy_secret (bool): If True, copies the Base64 key to the
        clipboard after encryption (filekey mode only). In password
        mode the salt is embedded in the file and does not need to
        be copied. Defaults to False. (optional)

    Error:
        File not found: sys.exit(1)
        Invalid filekey: sys.exit(1)
        Invalid password: sys.exit(1)
        Unexpected error: sys.exit(1)
    """
    
    if not in_current_folder(filename):
        print(f"{filename} not in the current folder.")
        sys.exit(1)
    
    print(f"---- Encryption of {filename} ----")

    # No password given : function will be dealing with a filekey
    if psw is None:
        # No filekey given, a random key will be generated.
        # --keyfile = False
        if given_filekey is None:
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
                    " and symbols.")
                    continue

            # Filekey generation
            print(f"Filekey generation ({generated_filekey_name})...")
            key = Fernet.generate_key()
            with open(generated_filekey_name, 'wb') as filekey:
                filekey.write(key)

        # FILEKEY GIVEN
        if given_filekey is not None:
            if valid_filekey(given_filekey):
                generated_filekey_name = given_filekey
            else:
                sys.exit(1)

        # Filekey reading and retrieved as bytes
        if given_filekey is None:
            print("Generated filekey reading...")
        else:
            print(f"Given filekey reading ({generated_filekey_name})...")

        try:
            with open(generated_filekey_name, 'rb') as filekey:
                key = filekey.read() # key = bytes
        except FileNotFoundError:
            print(f"Error : No such keyfile : {filename} in the current folder.")
            sys.exit(1)

        # Fernet object creation with the generated key
        f = Fernet(key)

    # Password given : function will be dealing without a 
    # filekey
    else:
        # Password mode: validate password, generate salt automatically
        if not valid_password(psw):
            sys.exit(1)

        f, salt_bytes = psw_derivation(psw)

    # Copying the file before overwriting it
    if not overwrite:
        name = filename[:filename.find('.')]
        name += "(copy)"
        ext = filename[filename.find('.'):]
        copy_filename = name + ext
        print("File copy before overwriting...")
        try:
            copyfile(filename, copy_filename)
        except FileNotFoundError:
            print(f"Error : No such file : {filename} " 
                  "in the current folder.")
            if psw is None:
                remove(generated_filekey_name)
            sys.exit(1)
        
    # Recovery the file to be encrypted in bytes
    print(f"{filename} reading...")
    try:
        with open(filename, 'rb') as file:
            file_bytes = file.read() # file_bytes = bytes
    except FileNotFoundError:
        print(f"Error : No such file : {filename} in the "
              "current folder.")
        if psw is None:
            remove(generated_filekey_name)
        sys.exit(1)

    # Bytes data encryption
    print(f"Data encryption...")
    encrypted = f.encrypt(file_bytes)

    # Overwriting the file with encrypted bytes data
    # In password mode: prepend the raw 16-byte salt so it can be
    # recovered automatically at decryption time.
    print(f"Encrypted data writing...")
    with open(filename, 'wb') as encrypted_file:
        if psw is not None:
            encrypted_file.write(salt_bytes + encrypted)
        else:
            encrypted_file.write(encrypted)

    print(f"---- Operation completed successfully ----")
    if given_filekey is None and psw is None:
        print("A keyfile has been generated in the " 
              "current folder, please keep it safe.")

    # Copy the filekey's Base64 key to the clipboard if requested
    # (filekey mode only; in password mode the salt is embedded in the
    # file and is inspectable via 'getsalt' — nothing sensitive to copy)
    if copy_secret and psw is None:
        secret_to_copy = key.decode('ascii')
        secret_label = f"Key from '{generated_filekey_name}'"

        try:
            pyperclip.copy(secret_to_copy)
            print(f"{secret_label} copied to clipboard.")
            print("Don't forget to clean the clipboard after use "
                  "('clean' command).")
        except pyperclip.PyperclipException:
            if USER_OS == "linux":
                if _copy_linux_native(secret_to_copy):
                    print(f"{secret_label} copied to clipboard.")
                    print("Don't forget to clean the clipboard after use "
                          "('clean' command).")
                else:
                    _clipboard_no_mechanism_msg()
            else:
                raise

@safety_check
def decrypt(filename: str,
            filekey_name: Union[str, None] = None, 
            psw: Union[str, None] = None):
    """Decrypts a file in 2 different ways :

    1. By using a filekey present in the current folder
    2. By using a password (salt is read automatically from the file)

    These 2 methods are mutually exclusive.

    In password mode, the salt is recovered from the first 16 bytes
    of the encrypted file (where it was embedded at encryption time).
    The user only needs to provide the password.

    Args:
        filename (str): Name of file to be decrypted.

        filekey_name (str | None): Name of the filekey in the
        current folder to decrypt with. Defaults to None.
        
        psw (str | None): Password to decrypt the file.
        Defaults to None.

    Error:
        File not found  : sys.exit(1)
        Invalid filekey : sys.exit(1)
        Invalid psw     : sys.exit(1)
        Invalid token   : sys.exit(1)
    """
    
    if not in_current_folder(filename):
        print(f"{filename} not in the current folder.")
        sys.exit(1)

    print(f"---- Decryption of {filename} ----")

    # ── Filekey mode ─────────────────────────────────────────────────
    if psw is None:
        if not valid_filekey(filekey_name):
            sys.exit(1)

        print(f"Filekey reading ({filekey_name})...")
        try:
            with open(filekey_name, 'rb') as filekey:
                key = filekey.read()
        except FileNotFoundError:
            print(f"Error : No such filekey : '{filekey_name}'"
            " in the current folder.")
            sys.exit(1)

        try:
            f = Fernet(key)
        except ValueError as e:
            print(f"Error : Invalid filekey — {e}")
            sys.exit(1)

        print(f"{filename} reading...")
        try:
            with open(filename, 'rb') as ef:
                encrypted = ef.read()
        except FileNotFoundError:
            print(f"Error : No such file : '{filename}' in the current folder")
            sys.exit(1)

    # ── Password mode ─────────────────────────────────────────────────
    # Salt is extracted from the first 16 bytes of the encrypted file
    else:
        if not valid_password(psw):
            sys.exit(1)

        print(f"{filename} reading...")
        try:
            with open(filename, 'rb') as ef:
                raw = ef.read()
        except FileNotFoundError:
            print(f"Error : No such file : '{filename}' in the current folder")
            sys.exit(1)

        if len(raw) < 17:
            print("Error: file too short to contain an embedded salt.")
            sys.exit(1)

        salt_bytes = raw[:16]
        encrypted  = raw[16:]
        print("Salt recovered from file...")
        f, _ = psw_derivation(psw, salt_bytes)

    # File data decryption
    print("Decrypting data...")
    try:
        decrypted = f.decrypt(encrypted)
    except InvalidToken:
        print("Error : Invalid Fernet token")
        sys.exit(1)

    # Overwriting the file with decrypted bytes
    print(f"{filename} writing...")
    with open(filename, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

    print(f"---- Operation completed successfully ----")

def verify(filename: str,
           filekey_name: Union[str, None] = None,
           psw: Union[str, None] = None) -> None:
    """Verifies that a filekey or a password is compatible with an
    encrypted file, without writing anything to disk.

    The file is read and decryption is attempted entirely in memory.
    The decrypted result is immediately discarded — the file on disk
    is never modified.

    In password mode, the salt is extracted automatically from the
    first 16 bytes of the file. The user only needs to provide the
    password.

    Mirrors decrypt() in its two modes but is strictly read-only.

    Args:
        filename (str): Name of the encrypted file to check.

        filekey_name (str | None): Filekey to verify against
        (with its .key extension). Mutually exclusive with psw.
        Defaults to None.

        psw (str | None): Password to verify against.
        Mutually exclusive with filekey_name. Defaults to None.

    Error:
        File not found     : sys.exit(1)
        Invalid filekey    : sys.exit(1)
        Invalid psw        : sys.exit(1)
        Wrong key/password : informs user, sys.exit(1)
    """
    if not in_current_folder(filename):
        print(f"{filename} not in the current folder.")
        sys.exit(1)

    if not exists(filename):
        print(f"Error: \'{filename}\' not found in the current folder.")
        sys.exit(1)

    # ── Filekey mode ──────────────────────────────────────────────────
    if psw is None:
        if not valid_filekey(filekey_name):
            sys.exit(1)

        try:
            with open(filekey_name, 'rb') as fk:
                key = fk.read()
        except FileNotFoundError:
            print(f"Error: filekey \'{filekey_name}\' not found.")
            sys.exit(1)

        try:
            f = Fernet(key)
        except ValueError as e:
            print(f"Error: Invalid filekey — {e}")
            sys.exit(1)

        key_label = f"Filekey \'{filekey_name}\'"

        try:
            with open(filename, 'rb') as ef:
                encrypted = ef.read()
        except FileNotFoundError:
            print(f"Error: \'{filename}\' not found in the current folder.")
            sys.exit(1)

    # ── Password mode ─────────────────────────────────────────────────
    # Salt is extracted automatically from the first 16 bytes
    else:
        if not valid_password(psw):
            sys.exit(1)

        try:
            with open(filename, 'rb') as ef:
                raw = ef.read()
        except FileNotFoundError:
            print(f"Error: \'{filename}\' not found in the current folder.")
            sys.exit(1)

        if len(raw) < 17:
            print("Error: file too short to contain an embedded salt.")
            sys.exit(1)

        salt_bytes = raw[:16]
        encrypted  = raw[16:]
        f, _ = psw_derivation(psw, salt_bytes)
        key_label = "The given password"

    # Attempt in-memory decryption — result is intentionally discarded
    try:
        f.decrypt(encrypted)
        print(f"\u2713 Verification successful.")
        print(f"  {key_label} can decrypt \'{filename}\'.")
    except InvalidToken:
        print(f"\u2717 Verification failed.")
        print(f"  {key_label} cannot decrypt \'{filename}\'.")
        print("  The password may be wrong, or the file may not be "
              "a valid password-encrypted Fernet token.")
        sys.exit(1)

def get_salt(filename: str, copy_secret: bool = False) -> None:
    """Extracts and displays the salt embedded in a password-encrypted file.

    When a file is encrypted with a password, a random 16-byte salt is
    prepended to the Fernet token. This function reads those first 16
    bytes and displays the salt as a Base64 urlsafe string.

    The salt is public by nature and its display poses no security risk.
    It can be useful for inspection, archiving, or debugging purposes.

    Args:
        filename (str): Password-encrypted file in the current folder.

        copy_secret (bool): If True, copies the salt to the clipboard
        using the pyperclip -> native Linux cascade. Defaults to False.

    Error:
        File not found        : sys.exit(1)
        File too short        : sys.exit(1)
    """
    if not in_current_folder(filename):
        print(f"{filename} not in the current folder.")
        sys.exit(1)

    if not exists(filename):
        print(f"Error: '{filename}' not found in the current folder.")
        sys.exit(1)

    try:
        with open(filename, 'rb') as f:
            salt_bytes = f.read(16)
    except OSError as e:
        print(f"Error reading '{filename}': {e}")
        sys.exit(1)

    if len(salt_bytes) < 16:
        print("Error: file too short to contain an embedded salt.")
        print("This file may not have been encrypted with a password.")
        sys.exit(1)

    salt_b64 = base64.urlsafe_b64encode(salt_bytes).decode('ascii')
    print(f"Salt: {salt_b64}")

    if copy_secret:
        try:
            pyperclip.copy(salt_b64)
            print("Salt copied to clipboard.")
            print("Don't forget to clean the clipboard after use "
                  "('clean' command).")
        except pyperclip.PyperclipException:
            if USER_OS == "linux":
                if _copy_linux_native(salt_b64):
                    print("Salt copied to clipboard.")
                    print("Don't forget to clean the clipboard after use "
                          "('clean' command).")
                else:
                    _clipboard_no_mechanism_msg()
            else:
                raise

# ===================================================================
#                             ARGPARSER
# ===================================================================
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

    # - - - - - - Command : psw
    parser_psw = subparsers.add_parser(
        "psw",
        help="Generates a strong random password"
    )
    parser_psw.add_argument(
        "-cs", "--copysecret",
        default=False, action="store_true",
        help="Copy the generated password to the clipboard"
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
        help="Password used to encrypt the file (salt is recovered "
             "automatically from the file)",
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

    # - - - - - - Command : delete
    parser_delete = subparsers.add_parser(
        "delete",
        help="Securely deletes a file from the current folder"
    )
    parser_delete.add_argument(
        "filenames",
        nargs='+',
        help="The file name(s) to delete (one or more)"
    )
    parser_delete.add_argument("-s", "--shuffle", default= False, 
        help="Shuffle file bytes before deletion", action="store_true")

    # - - - - - - Command : zip
    parser_zip = subparsers.add_parser(
    "zip",
    help="Zip files/folders"
    )
    
    parser_zip.add_argument(
        "targets", 
        nargs='+', 
        help="Files or folders to zip"
    )

    parser_zip.add_argument(
        "-d", "--delete",
        default=False,
        action="store_true",
        help="Deletes original files after archiving"
    )

    # - - - - - - Command : unzip
    parser_unzip = subparsers.add_parser(
        "unzip", help="Unzip a file/folder"
    )
    parser_unzip.add_argument(
        "arcname", help="Archive to unzip"
    )

    # - - - - - - Command : clean
    parser_clean = subparsers.add_parser(
        "clean", help="Cleans the clipboard"
    )

    # - - - - - - Command : copykey
    parser_copykey = subparsers.add_parser(
        "copykey",
        help="Copy a filekey's Base64 key to the clipboard"
    )
    parser_copykey.add_argument(
        "filekey",
        help="Filekey name (with its .key extension)"
    )

    # - - - - - - Command : getsalt
    parser_getsalt = subparsers.add_parser(
        "getsalt",
        help="Extract the salt embedded in a password-encrypted file"
    )
    parser_getsalt.add_argument(
        "filename",
        help="Password-encrypted file (with its extension)"
    )
    parser_getsalt.add_argument(
        "-cs", "--copysecret",
        default=False, action="store_true",
        help="Copy the extracted salt to the clipboard"
    )

    # - - - - - - Command : encrypt
    parser_encrypt = subparsers.add_parser("encrypt",
        help= "Encrypts a file")
    parser_encrypt.add_argument("filename",
        help= "File name to be encrypted (with its extension)")
    parser_encrypt.add_argument("-f", "--filekey",
        help= "Name of the existing filekey (with its extension)", default=None)
    parser_encrypt.add_argument("-p", "--password", default= None,
        help= "Encrypts with a given password (salt is generated and "
             "embedded automatically)", action="store_true")

    parser_encrypt.add_argument(
        "-cs", "--copysecret",
        default=False, action="store_true",
        help="After encryption, copy the filekey's Base64 key to the "
             "clipboard (filekey mode only; in password mode the salt "
             "is embedded in the file and retrieved via 'getsalt')"
    )

    # The -overwrite and -copy options are mutually exclusive.
    # Both are optional: if neither is provided, --copy is
    # applied by default as a safety measure.
    group_encrypt = parser_encrypt.add_mutually_exclusive_group(required=False)
    group_encrypt.add_argument("-ow", "--overwrite",
        action="store_true", help="Overwrites the original file")
    group_encrypt.add_argument("-c", "--copy",
        action="store_true", help="Copy the file before overwriting it "
        "in its encrypted version (default if neither option is given)")

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
        default= None, help= "Decrypts with a given password (salt is "
        "recovered automatically from the file)", 
        action="store_true")

    # - - - - - - Command : verify
    parser_verify = subparsers.add_parser(
        "verify",
        help="Verify that a key/password can decrypt a file "
             "(read-only, nothing is written to disk)"
    )
    parser_verify.add_argument(
        "filename",
        help="Encrypted file to verify (with its extension)"
    )
    parser_verify.add_argument(
        "filekey", nargs="?",
        help="Filekey to verify against (with its .key extension). "
             "Omit if using --password."
    )
    parser_verify.add_argument(
        "-p", "--password",
        default=None, action="store_true",
        help="Verify using a password instead of a filekey (salt is "
             "recovered automatically from the file)"
    )

        # - - - - - - Call logics - - - - - -
    args = parser.parse_args()

    if args.command == "install":
        install_from_requirements()
    
    elif args.command == "psw":
        psw_gen(copy_secret=args.copysecret)

    elif args.command == "read":
        read_filekey(args.filekey)
    
    elif args.command == "timestamp":
        # Conflict
        if args.filekey and args.password:
            print("ERROR : You must provide either a 'filekey' or a "
                "'--password'.")
            sys.exit(1)

        # File encrypted with a filekey
        elif args.filekey:
            get_timestamp(encrypted_file=args.encrypted_file,
                          filekey=args.filekey)

        # Password mode: salt is recovered automatically from the file
        elif args.password:
            password = get_confidential_input("Password: ")
            get_timestamp(encrypted_file=args.encrypted_file,
                          psw=password)

        else:
            print("Wrong command combination.")
            sys.exit(1)

    elif args.command == "create":
        key = get_confidential_input("Key: ")
        create_filekey(args.filename, key)
    
    elif args.command == "delete":
        # Single file/folder : standard behaviour (confirmation inside secure_delete)
        if len(args.filenames) == 1:
            secure_delete(args.filenames[0], shuffle=args.shuffle)

        # Multiple targets : one global confirmation before processing
        else:
            print("You are about to irreversibly delete the following targets:")
            for filename in args.filenames:
                if isdir(filename):
                    file_count = sum(len(files) for _, _, files in walk(filename))
                    print(f"  [folder] {filename}/ ({file_count} file(s))")
                else:
                    print(f"  [file]   {filename}")

            choice = None
            while choice != "y" and choice != "n":
                choice = input("Do you confirm this operation? (y/n): ").lower()
                if choice == "n":
                    print("Exiting...")
                    sys.exit(0)
                elif choice != "y":
                    print("Invalid input.")

            for filename in args.filenames:
                secure_delete(filename, shuffle=args.shuffle, silent_mode=True)
                print(f"  '{filename}' has been deleted.")
    
    elif args.command == "zip":
        zip_files(args.targets, args.delete)
    
    elif args.command == "unzip":
        unzip_file(args.arcname)

    elif args.command == "clean":
        clean()

    elif args.command == "copykey":
        copy_filekey(args.filekey)

    elif args.command == "encrypt":
        password = None

        if args.password and args.filekey:
            print("ERROR : You must provide either a 'filekey' or a "
                "'--password'.")
            sys.exit(1)

        if args.password:
            password = get_confidential_input("Password: ")

        if args.overwrite:
            encrypt(args.filename, overwrite=True,
                    given_filekey=args.filekey,
                    psw=password,
                    copy_secret=args.copysecret)

        else:
            # --copy explicitly given, or neither option provided
            # (--copy is the default for safety)
            if not args.copy:
                print("Note: no mode specified, defaulting to --copy")
            encrypt(args.filename, overwrite=False,
                    given_filekey=args.filekey,
                    psw=password,
                    copy_secret=args.copysecret)

    elif args.command == "decrypt":
        # Wrong command
        if (args.password is None and args.filekey is None) or (args.password and args.filekey):
            print("ERROR : You must provide either a 'filekey' or a "
                "'--password'.")
            sys.exit(1)

        # Password mode: salt is recovered automatically from the file
        elif args.password:
            password = get_confidential_input("Password: ")
            decrypt(args.filename, psw=password)

        # Filekey mode
        else:
            decrypt(args.filename, args.filekey)

    elif args.command == "verify":
        # Conflict : both filekey and --password provided
        if args.filekey and args.password:
            print("ERROR : You must provide either a 'filekey' or "
                  "'--password', not both.")
            sys.exit(1)

        # Neither provided
        elif not args.filekey and not args.password:
            print("ERROR : You must provide either a 'filekey' or "
                  "'--password'.")
            sys.exit(1)

        # Password mode: salt is recovered automatically from the file
        elif args.password:
            password = get_confidential_input("Password: ")
            verify(args.filename, psw=password)

        # Filekey mode
        else:
            verify(args.filename, filekey_name=args.filekey)

    elif args.command == "getsalt":
        get_salt(args.filename, copy_secret=args.copysecret)

    else:
        print("ERROR : Unknown argument.")
        sys.exit(1)

if __name__ == "__main__":
    main()