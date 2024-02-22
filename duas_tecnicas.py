import hashlib
import time

def encrypt_password(password, method='md5'):
    """
    Criptografa a senha usando o algoritmo especificado.
    """
    if len(password) > 8:
        raise ValueError("A senha deve ter no máximo 8 caracteres.")
    
    # Codifica a senha como bytes antes de criptografar
    password_bytes = password.encode('utf-8')
    
    # Escolha do método de criptografia
    if method == 'sha256':
        hash_obj = hashlib.sha256()
    elif method == 'md5':
        hash_obj = hashlib.md5()
    else:
        raise ValueError("Método de criptografia não suportado.")
    
    # Atualiza o objeto de hash com os bytes da senha
    hash_obj.update(password_bytes)
    
    # Retorna a representação hexadecimal da hash
    return hash_obj.hexdigest()

def crack_password(encrypted_password, method='md5'):
    """
    Tenta quebrar a senha usando força bruta.
    """
    start_time = time.time()
    found = False
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    
    for c1 in chars:
        for c2 in chars:
            for c3 in chars:
                for c4 in chars:
                    for c5 in chars:
                        for c6 in chars:
                            for c7 in chars:
                                for c8 in chars:
                                    password = c1 + c2 + c3 + c4 + c5 + c6 + c7 + c8
                                    encrypted = encrypt_password(password, method)
                                    if encrypted == encrypted_password:
                                        found = True
                                        break
                                if found:
                                    break
                            if found:
                                break
                        if found:
                            break
                    if found:
                        break
                if found:
                    break
            if found:
                break
        if found:
            break
    
    end_time = time.time()
    if found:
        print(f"Senha quebrada: {password}")
    else:
        print("Senha não foi quebrada.")
    print(f"Tempo decorrido: {end_time - start_time} segundos.")

# Testando as funções
senha = input("Digite a senha (máximo de 8 caracteres): ")
senha_criptografada = encrypt_password(senha)
print(f"Senha criptografada: {senha_criptografada}")

senha = input("Digite a senha a ser quebrada (criptografada: ")
crack_password(senha)
