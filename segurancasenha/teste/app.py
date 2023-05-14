from flask import Flask, render_template, request, redirect, url_for
from senhateste import validar_senha, enviar_email_alerta, salvar_senha_db, gerar_chave
import socket
import os

app = Flask(__name__)

# Variáveis globais para armazenar o email e as tentativas de senha
user_email = None
failed_attempts = 0

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        salt = os.urandom(16)
        fernet = gerar_chave(senha, salt)
        senha_encriptada = fernet.encrypt(senha.encode())
        salvar_senha_db(email, senha_encriptada, salt)
        return redirect(url_for('login'))
    return render_template('registro.html')

@app.route('/verificar', methods=['POST'])
def verificar():
    global user_email, failed_attempts

    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        if user_email != email:
            user_email = email
            failed_attempts = 0

        if validar_senha(email, senha):
            failed_attempts = 0
            return render_template('registro.html')  # Página de sucesso
        else:
            failed_attempts += 1
            if failed_attempts >= 3:
                failed_attempts = 0
                ip = socket.gethostbyname(socket.gethostname())
                enviar_email_alerta(email, ip, tentativa_acesso=True)  # Função para enviar e-mail de alerta
                return render_template('registro.html')  # Página de alerta de força bruta
            else:
                return render_template('login.html', error=f"Senha incorreta! Tentativas restantes: {3 - failed_attempts}")

if __name__ == '__main__':
    app.run(debug=True)
