#encriptar uma senha dada pelo usuário, armazenar num banco de dados e depois validar a senha encriptada
#pip install cryptography
import re
import os
import sqlite3
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
from cryptography.hazmat.backends import default_backend

def verificar_senha(senha):
    #se tiver mais de 8 digitos
    if len(senha) < 8:
        return False
    if not re.search("[A-Z]", senha):
        return False
    if not re.search("[0-9]", senha):
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", senha):
        return False
    return True