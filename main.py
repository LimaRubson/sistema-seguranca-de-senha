import hashlib
import time
import itertools
import secrets

def cadastrar_usuario():
    username = input("Digite o nome de usuário: ")
    senha = input("Digite a senha (máximo 8 caracteres): ")
    if len(senha) > 8:
        print("A senha deve ter no máximo 8 caracteres.")
        return
    # Gerar um salt aleatório
    salt = secrets.token_hex(16)
    # Concatenar a senha com o salt e hash
    senha_hash = hashlib.sha256((senha + salt).encode()).hexdigest()
    return {'username': username, 'senha_hash': senha_hash, 'salt': salt}

def autenticar_usuario(usuarios, username, senha):
    for usuario in usuarios:
        if usuario['username'] == username:
            # Calcular hash da senha inserida com o salt
            senha_hash = hashlib.sha256((senha + usuario['salt']).encode()).hexdigest()
            # Verificar se as senhas hash são iguais
            if usuario['senha_hash'] == senha_hash:
                return True
    return False

def quebrar_senha(usuarios, senha_hash):
    caracteres = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    for usuario in usuarios:
        start_time = time.time()
        for i in range(1, 9):
            for comb in itertools.product(caracteres, repeat=i):
                print("Tentando...")
                tentativa = ''.join(comb)
                tentativa_hash = hashlib.sha256((tentativa + usuario['salt']).encode()).hexdigest()
                if tentativa_hash == senha_hash:
                    end_time = time.time()
                    tempo_gasto = end_time - start_time
                    return tentativa, tempo_gasto
    return None, None


def main():
    usuarios = []

    while True:
        print("\n1. Cadastrar usuário")
        print("2. Autenticar usuário")
        print("3. Quebrar senha")
        print("4. Sair")

        opcao = input("\nEscolha uma opção: ")

        if opcao == '1':
            usuario = cadastrar_usuario()
            if usuario:
                usuarios.append(usuario)
                print("Usuário cadastrado com sucesso.")
        elif opcao == '2':
            username = input("Digite o nome de usuário: ")
            senha = input("Digite a senha: ")
            if autenticar_usuario(usuarios, username, senha):
                print("Usuário autenticado com sucesso.")
            else:
                print("Nome de usuário ou senha incorretos.")
        elif opcao == '3':
            senha_hash = input("Digite a senha hash a ser quebrada: ")
            senha_quebrada, tempo_gasto = quebrar_senha(usuarios, senha_hash)
            if senha_quebrada:
                print(f"Senha quebrada: {senha_quebrada}")
                print(f"Tempo gasto: {tempo_gasto} segundos.")
            else:
                print("Senha não foi quebrada.")
        elif opcao == '4':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
