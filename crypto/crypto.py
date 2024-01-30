import os
import base64
from io import BytesIO
from datetime import datetime
# from django.conf import settings
# from django.core.files import File
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
from django.core.files.base import ContentFile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SEPARATOR = "\n-----\n"


def generate_key(user_key):
    """Generate key for encryption/decryption."""

    password = user_key.encode()

    # Salt for SHA256 hash
    # salt = b'StrongestAvenger__HULK'
    salt = b'Xj4jA}AZF^j(9CYkl9}9tta/dQhDJWP**TRHrfM2tt2OQIQ&+q'

    # Generate Hash
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    # Key used for encryption/decryption
    key = base64.urlsafe_b64encode(kdf.derive(password))

    return key


def encipher(message, user_key):
    """Encrypt"""

    plain_text = message.encode()

    f = Fernet(user_key)

    cipher = f.encrypt(plain_text)

    return cipher


def decipher(message, user_key):
    """Decrypt"""

    try:
        cipher_text = message.encode()

        f = Fernet(user_key)

        plain = f.decrypt(cipher_text)

        return plain
    except:
        return 0


def encrypt_backup_key(key):
    """Encrypt the backup key used for recovery."""
    backup_key = generate_key("BACKUP")
    return encipher(key, backup_key).decode("utf-8")


def encrypt(key, file_instance):
    """
    Encrypt file.
    """

   # ENCRYPTION KEY
    key = generate_key(key)

    # READ FILE
    encoded_data = b64encode(file_instance.read())

    # CREATE FILE NAME TO WRITE
    og_file_name = file_instance.name.split(
        os.path.sep).pop()
    file_name = (og_file_name + ".mis").replace(" ", "_")

    # WRITE META DATA
    file_contents = b""
    ext = og_file_name.split(".").pop()  # GET FILE EXTENSION
    meta = "{} | Encrypted By Make It Secret, {} | {}\n".format(
        ext,
        datetime.now(),
        encrypt_backup_key()
    )
    file_contents += meta.encode()

    # WRITE SEPARATOR
    file_contents += SEPARATOR.encode()

    # ENCRYPT DATA
    enc = encipher(encoded_data.decode("utf-8"), key)

    # WRITE ENCRYPTED DATA
    file_contents += enc

    file_contents = BytesIO(b64decode(enc))
    content_file = ContentFile(file_contents.getvalue(), file_name)

    return content_file


def decrypt(key, file_instance):
    """
    Decrypt file.
    """

    # DECRYPTION KEY
    key = generate_key(key)

    # READ FILE
    content = file_instance.read().decode("utf-8")

    # READ META INFORMATION
    meta = content.split(SEPARATOR)[0]

    # GET ORIGINAL FILE EXTENSION FROM HEADER
    ext = ".{}".format(
        meta.split(" | ")[0]
    )

    # CREATE ORIGINAL FILE NAME
    file_name = file_instance.name.split(
        os.path.sep).pop().split(".").pop() + ext

    # GET FILE CONTENTS
    file_content = content.split(SEPARATOR)[-1].encode()

    # DECRYPT DATA
    dec = decipher(file_content.decode("utf-8"), key)

    if dec == 0:
        # KEY MISMATCH
        raise Exception("Key Mismatch")

    file_contents = BytesIO(b64decode(dec))
    content_file = ContentFile(file_contents.getvalue(), file_name)

    return content_file
