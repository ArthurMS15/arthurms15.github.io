#encriptar uma senha dada pelo usuário, armazenar num banco de dados e depois validar a senha encriptada

def verificar_senha(senha):
    #se tiver mais de 8 digitos
    if len(senha) < 8:
        return False
    #verificar maiusculo
        return False
    #verificar número
        return False
    #verificar se possui caracteres especiais
        return False
    return True