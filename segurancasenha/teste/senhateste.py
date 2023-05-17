import re
import os #ler e escrever arquivos
import base64 #dados binários para uma forma que pode ser impressa ou transmitida de forma segura
import sqlite3
import socket

from email.message import EmailMessage
from getpass import getpass #ocultar a entrada do usuário
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC #função de derivação de chave, código de autenticação de mensagem que usa uma função hash criptográfica em combinação com uma chave secreta.
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC #outra função de derivação de chave que combina os dados de entrada 
from cryptography.hazmat.backends import default_backend

#autorização do OAuth 2.0 e interação com API google
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pickle
from google.auth.transport.requests import Request

# Se modificar o escopo, exclua o arquivo token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def verificar_senha(senha):
    if len(senha) < 8:
        return False
    if not re.search("[A-Z]", senha):
        return False
    if not re.search("[0-9]", senha):
        return False
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", senha):
        return False
    return True

def get_credentials():
    creds = None
    # O arquivo token.pickle armazena as credenciais do usuário.
    # Ele é criado automaticamente ao executar pela primeira vez.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # Se não houver credenciais válidas, deixe o usuário fazer login.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Salve as credenciais para a próxima execução
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return creds

def enviar_email_alerta(email, ip, tentativa_acesso=True):
    msg = EmailMessage()
    
    if tentativa_acesso:
        msg.set_content(f"Alguém tentou acessar sua conta por meio de força bruta\nIP: {ip}")
        msg["Subject"] = "Alerta de tentativa de acesso"
    else:
        msg.set_content(f"Seu acesso foi realizado com sucesso\nIP: {ip}")
        msg["Subject"] = "Acesso bem-sucedido"

    msg["From"] = "seu_email@example.com"  # Insira seu e-mail aqui
    msg["To"] = email

    try:
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
        service = build("gmail", "v1", credentials=creds)
        raw_msg = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        send_message = {"raw": raw_msg}
        service.users().messages().send(userId="me", body=send_message).execute()
        print("E-mail de alerta enviado com sucesso.")
    except Exception as e:
        print(f"Erro ao enviar e-mail: {e}")

def gerar_chave(password, salt):
    backend = default_backend()
    kdf_pbkdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    intermediate_key = kdf_pbkdf2.derive(password.encode())

    kdf_concat = ConcatKDFHMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        backend=backend
    )
    final_key = kdf_concat.derive(intermediate_key)
    
    return Fernet(base64.urlsafe_b64encode(final_key))

def salvar_senha_arquivo(senha_encriptada):
    with open("senha_encriptada.txt", "wb") as arquivo:
        arquivo.write(senha_encriptada)


def salvar_senha_db(email, senha_encriptada, salt):
    conn = sqlite3.connect("senhas.db")
    cursor = conn.cursor()

    cursor.execute(
        "CREATE TABLE IF NOT EXISTS senhas (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, salt BLOB, senha_encriptada BLOB)"
    )

    cursor.execute(
        "INSERT INTO senhas (email, salt, senha_encriptada) VALUES (?, ?, ?)",
        (email, salt, senha_encriptada),
    )

    conn.commit()
    conn.close()

def validar_senha(email, senha):
    conn = sqlite3.connect("senhas.db")
    cursor = conn.cursor()

    cursor.execute("SELECT salt, senha_encriptada FROM senhas WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    if row:
        salt, senha_encriptada_db = row
        fernet = gerar_chave(senha, salt)
        try:
            fernet.decrypt(senha_encriptada_db)
            print("Senha validada com sucesso!")
            ip = socket.gethostbyname(socket.gethostname())
            enviar_email_alerta(email, ip, tentativa_acesso=False)
            return True
        except Exception:
            print("Senha incorreta!")
            return False
    else:
        print("Nenhuma senha encontrada no banco de dados.")
        return False

def main():
    email = input("Digite seu e-mail: ")
    senha = getpass("Digite uma senha que atenda às restrições: ")
    while not verificar_senha(senha):
        print("Senha inválida. Certifique-se de que a senha tenha pelo menos 8 caracteres, um número, uma letra maiúscula e um caractere especial.")
        senha = getpass("Digite uma senha que atenda às restrições: ")

    salt = os.urandom(16)
    fernet = gerar_chave(senha, salt)
    senha_encriptada = fernet.encrypt(senha.encode())

    salvar_senha_arquivo(senha_encriptada)
    print("Senha encriptada salva no arquivo 'senha_encriptada.txt'.")

    salvar_senha_db(email, senha_encriptada, salt)
    print("Senha encriptada salva no banco de dados.")
    
    tentativas = 3
    while tentativas > 0:
        senha_teste = getpass("Digite sua senha para verificar: ")
        if validar_senha(email, senha_teste):
            break
        else:
            tentativas -= 1
            print(f"Senha incorreta! Tentativas restantes: {tentativas}")
            if tentativas == 0:
                print("Você excedeu o limite de tentativas.")
                ip = socket.gethostbyname(socket.gethostname())
                enviar_email_alerta(email, ip, tentativa_acesso=True)

if __name__ == "__main__":
    main()


