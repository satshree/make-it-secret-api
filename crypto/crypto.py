# import os
import pytz
import base64
from io import BytesIO
from datetime import datetime
from django.conf import settings
# from django.core.files import File
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
from django.core.files.base import ContentFile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from .utilities import parse_date
from .exceptions import KeyMismatchException

SEPARATOR = "\n-----\n"


def generate_key(user_key):
    """Generate key for encryption/decryption."""

    password = user_key.encode()

    # Salt for SHA256 hash
    salt = settings.ENCRYPTION_KEY_SALT.encode()

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


def encrypt(key, file_instance):
    """
    Encrypt file.
    """

   # ENCRYPTION KEY
    key = generate_key(key)

    # READ FILE
    file_data = b64encode(file_instance.read()).decode("utf-8")

    # CREATE FILE NAME TO WRITE
    file_name_split = file_instance.name.split(".")

    ext = file_name_split[-1]  # GET FILE EXTENSION
    del file_name_split[-1]

    og_file_name = "".join(file_name_split)
    file_name = (og_file_name + ".mis")  # .replace(" ", "_")

    # WRITE META DATA
    file_contents = b""

    meta = "{} | Encrypted By Make It Secret, {}\n".format(
        ext,
        datetime.now().astimezone(tz=pytz.timezone(settings.TIME_ZONE))
    )
    file_contents += meta.encode()

    # WRITE SEPARATOR
    file_contents += SEPARATOR.encode()

    # ENCRYPT DATA
    enc = encipher(file_data, key)

    # WRITE ENCRYPTED DATA
    file_contents += enc

    file_contents = BytesIO(file_contents)
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
    file_name_split = file_instance.name.split(".")
    del file_name_split[-1]
    file_name = "".join(file_name_split) + ext

    # GET FILE CONTENTS
    file_content = content.split(SEPARATOR)[-1]  # .encode()

    # DECRYPT DATA
    dec = decipher(file_content, key)

    if dec == 0:
        # KEY MISMATCH
        raise KeyMismatchException

    file_contents = BytesIO(b64decode(dec))
    content_file = ContentFile(file_contents.getvalue(), file_name)

    return content_file
