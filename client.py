# terminal
import os

# constants
import constant

# tcp
import socket

# crypto suport
import cript

# passwords
from getpass import getpass

# intrusion
import time

# decode
import base64


class Client:
    def __init__(self):
        print(
            f"{constant.bcolors.HEADER}\nInfo: Criando instância de cliente.{constant.bcolors.ENDC}")
        self.connection()

    def connection(self):
        print(
            f"{constant.bcolors.HEADER}\nInfo: Criando socket.{constant.bcolors.ENDC}")
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print("Usando endereço...{} na porta...{}".format(
            socket.gethostbyname(socket.gethostname()), constant.PORT))
        self.tcp.connect((socket.gethostbyname(
            socket.gethostname()), constant.PORT))

        print(
            f"{constant.bcolors.FAIL}Iniciando testes iniciais entre cliente-servidor...{constant.bcolors.ENDC}")
        if self.connection_test() and self.chap_test() and self.aes_test(self.dhke_test()):
            print(
                f"{constant.bcolors.FAIL}Todos os testes iniciais, entre cliente e servidor, efetuados com sucesso!\n{constant.bcolors.ENDC}")
            return True
        else:
            return False

    def connection_test(self):
        print(
            f"{constant.bcolors.HEADER}\nInfo: My Three-Way Handshake...{constant.bcolors.ENDC}")

        msg = "-Fala, benca!"
        self.tcp.sendall(msg.encode())
        print(f"{constant.bcolors.WARNING}Enviando mensagem:",
              msg, f"{constant.bcolors.ENDC}")

        msg = self.tcp.recv(constant.BUFFSIZE).decode('utf-8')
        print(f"{constant.bcolors.OKGREEN}Mensagem recebida:",
              msg, f"{constant.bcolors.ENDC}")
        if msg == "--Dahle.":

            msg = "-Bora, baratinar :)"
            self.tcp.sendall(msg.encode())
            print(f"{constant.bcolors.WARNING}Enviando mensagem:",
                  msg, f"{constant.bcolors.ENDC}")

            print("Protocolo efetuado com sucesso.")
            return True
        print("Erro: Falha no protocolo.")
        return False

    def chap_test(self):
        return self.chap(True)  # on start, use False

    def chap(self, autotest):
        print(f"{constant.bcolors.HEADER}\nChallenge-Handshake Authentication Protocol - CHAP - Client{constant.bcolors.ENDC}")

        nonce = self.tcp.recv(constant.NONCESIZE)
        print(f"{constant.bcolors.OKGREEN}Recebendo nonce para login...",
              base64.b85encode(nonce), f"{constant.bcolors.ENDC}")

        if not autotest:
            msg = input("Insira login>>> ")
        else:
            msg = "12345678901"
        hashmsg = cript.hash(cript.hash(msg.encode()), nonce)
        self.tcp.sendall(hashmsg)
        print(f"{constant.bcolors.WARNING}Enviando hash:",
              base64.b85encode(hashmsg), " de login:", msg, f"{constant.bcolors.ENDC}")

        nonce = self.tcp.recv(constant.NONCESIZE)
        print(f"{constant.bcolors.OKGREEN}Recebendo nonce para login...",
              base64.b85encode(nonce), f"{constant.bcolors.ENDC}")

        if not autotest:
            msg = getpass("Insira senha>>> ")
        else:
            msg = "123456"
        hashmsg = cript.hash(cript.hash(msg.encode()), nonce)
        self.tcp.sendall(hashmsg)
        print(f"{constant.bcolors.WARNING}Enviando hash:",
              base64.b85encode(hashmsg), " de senha:", msg, f"{constant.bcolors.ENDC}")

        msg = self.tcp.recv(constant.BUFFSIZE).decode('utf-8')
        if msg == "Olá admin! Bem-vindo, você está autenticado!":
            print(msg)
            return True
        else:
            print("Falha no login e senha. Tente novamente!")
            return False

    def dhke_test(self):
        return self.dhke()

    def dhke(self):
        print(
            f"{constant.bcolors.HEADER}\nDiffie Hellman Key Exchange - DHKE - Client{constant.bcolors.ENDC}")

        pubkeyServer = self.tcp.recv(constant.BUFFSIZE)
        print(f"{constant.bcolors.OKGREEN}Recebendo chave pública do servidor:",
              base64.b85encode(pubkeyServer), f"{constant.bcolors.ENDC}")

        p = cript.DH_init()
        pubkeyClient = cript.DH_send(p)
        self.tcp.sendall(pubkeyClient.to_bytes(constant.DIFFSIZE, 'big'))
        print(f"{constant.bcolors.WARNING}Enviando chave pública do cliente:",
              base64.b85encode(pubkeyClient.to_bytes(constant.DIFFSIZE, 'big')), f"{constant.bcolors.ENDC}")

        sharedkey = cript.DH_recv(
            p, int.from_bytes(pubkeyServer, byteorder='big'))
        print("Calculando chave compartilhada... {}".format(
            base64.b85encode(sharedkey.encode())))

        nonce = self.tcp.recv(constant.NONCESIZE)
        print(f"{constant.bcolors.OKGREEN}Recebendo nonce...",
              base64.b85encode(nonce), f"{constant.bcolors.ENDC}")

        hashmsg = cript.hash(sharedkey.encode(), nonce)
        self.tcp.sendall(hashmsg)
        print(f"{constant.bcolors.WARNING}Enviando hash...",
              base64.b85encode(hashmsg), f"{constant.bcolors.ENDC}")

        serverResponse = self.tcp.recv(constant.BUFFSIZE).decode('utf-8')
        if "Compartilhamento de chaves concluído com sucesso." == serverResponse:
            print(serverResponse)
            return sharedkey

        else:
            print(serverResponse)
            time.sleep(cript.randint(5, 10))
            return False

    def aes_crypt(self, msg, sharedkey):
        cipher = cript.encript(sharedkey, msg.encode())
        # self.conn.sendall(cipher)
        print(f"{constant.bcolors.WARNING}Mensagem enviada:",
              msg, "cifrada como:", cipher, f"{constant.bcolors.ENDC}")
        return cipher

    def aes_decrypt(self, cipher, sharedkey):
        msg = cript.decript(sharedkey, cipher).decode('utf-8')
        print(f"{constant.bcolors.OKGREEN}Mensagem recebida:",
              cipher, "decifrada como:", msg, f"{constant.bcolors.ENDC}")
        return msg

    def aes_test(self, sharedkey):
        print(f"{constant.bcolors.HEADER}\nMy Three-Way Handshake - AES Version - Client{constant.bcolors.ENDC}")

        self.tcp.sendall(self.aes_crypt("-Bote feh, Vei.", sharedkey))

        msg = self.aes_decrypt(self.tcp.recv(constant.BUFFSIZE), sharedkey)
        if msg == "--Deeeeeu a bixiga!":

            self.tcp.sendall(self.aes_crypt(
                "-Mermao, muito donzelo.", sharedkey))

            print("Comunicação segura por AES efetuada com sucesso.")
            return True
        return False

    def candidate_add(self, autotest, sharedkey):
        print(
            f"{constant.bcolors.HEADER}Cadastrando candidato...{constant.bcolors.ENDC}")

        sucess = False
        while not sucess:
            if not autotest:
                msg = input("Insira numero>>>")
            else:
                msg = "1234"
            self.tcp.sendall(self.aes_crypt(msg, sharedkey))
            if self.aes_decrypt(self.tcp.recv(constant.BUFFSIZE), sharedkey) == "Sucesso":
                sucess = True

        if not autotest:
            msg = input("Insira nome>>> ")
        else:
            msg = "Abdoral"
        self.tcp.sendall(self.aes_crypt(msg, sharedkey))

        print(self.aes_decrypt(self.tcp.recv(constant.BUFFSIZE), sharedkey))

    def voter_add(self, autotest, sharedkey):
        print(f"{constant.bcolors.HEADER}Cadastrando eleitor...{constant.bcolors.ENDC}")

        sucess = False
        while not sucess:
            if not autotest:
                msg = input("Insira cpf>>>")
            else:
                msg = "00000000000"
            self.tcp.sendall(self.aes_crypt(msg, sharedkey))
            if self.aes_decrypt(self.tcp.recv(constant.BUFFSIZE), sharedkey) == "Sucesso":
                sucess = True

        if not autotest:
            msg = input("Insira nome>>> ")
        else:
            msg = "E1E1T0R"
        self.tcp.sendall(self.aes_crypt(msg, sharedkey))

        if not autotest:
            msg = input("Insira senha>>> ")
        else:
            msg = "123456"
        self.tcp.sendall(self.aes_crypt(msg, sharedkey))

        msg = self.aes_decrypt(self.tcp.recv(constant.BUFFSIZE), sharedkey)
        if msg == "Candidato cadastrado com sucesso.":
            return True
        else:
            return False

    def logoff(self):
        print(f"{constant.bcolors.HEADER}Fazer Logoff...{constant.bcolors.ENDC}")

    def vote(self, autotest, sharedkey):
        print(
            f"{constant.bcolors.HEADER}Iniciando votação...{constant.bcolors.ENDC}")

        if not autotest:
            cpf = input("Insira cpf>>>")
            pswd = input("Insira senha>>>")
        else:
            cpf = "00000000000"
            pswd = "123456"
        self.tcp.sendall(self.aes_crypt(cpf, sharedkey))
        time.sleep(cript.randint(6, 9)) #sincroniscmo
        self.tcp.sendall(self.aes_crypt(pswd, sharedkey))        

        if self.aes_decrypt(self.tcp.recv(constant.BUFFSIZE), sharedkey) == "Permitido":
            if not autotest:
                voto = input("Insira numero do candidato>>>")
            else:
                voto = "1234"
            self.tcp.sendall(self.aes_crypt(voto, sharedkey))

    def report(self):
        status = True
        while status:
            msg = self.tcp.recv(constant.BUFFSIZE).decode("utf-8")
            if msg == "FIM":
                time.sleep(cript.randint(1, 2)) #sincroniscmo
                status = False
            else:
                print(msg)

    def shut(self):
        print("Finalizando execução do cliente...")
        self.tcp.close()

    def messenger(self, loops):
        msg = ""
        if loops == 0:
            msg = "Autenticar"
        elif loops == 1:
            msg = "Cadastrar Candidato"
        elif loops == 2:
            msg = "Cadastrar Eleitor"
        elif loops == 3:
            msg = "Logoff"
        elif loops == 4:
            msg = "Votar"
        elif loops == 5:
            msg = "Relatório"
        elif loops == 6:
            msg = "Fim da demonstração"
        elif loops == 7:
            msg = "Sair"
        return msg

    def run(self, autotest):
        run = True
        loops = 0
        while(run):
            print(f"{constant.bcolors.OKGREEN}\nLoop:",
                  loops, "Aguardando comando.", f"{constant.bcolors.ENDC}")

            if not autotest:
                msg = input("Insira comando>>> ")
            else:
                msg = self.messenger(loops)

            self.tcp.sendall(msg.encode())
            print(f"{constant.bcolors.WARNING}Enviando comando:",
                  msg, f"{constant.bcolors.ENDC}")

            if msg == "Autenticar":
                self.chap(autotest)
            elif msg == "Cadastrar Candidato":
                self.candidate_add(autotest, self.dhke())
            elif msg == "Cadastrar Eleitor":
                self.voter_add(autotest, self.dhke())
            elif msg == "Logoff":
                self.logoff()
            elif msg == "Votar":
                self.vote(autotest, self.dhke())
            elif msg == "Relatório":
                self.report()
            elif msg == "Sair":
                run = False
            else:
                print(f"{constant.bcolors.FAIL}Erro: Comando",
                      msg, "inválido.",  f"{constant.bcolors.ENDC}")

            loops += 1

        self.shut()


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Criando instância do cliente...")
    s = Client()
    s.run(True)
    s.shut()


if __name__ == "__main__":
    print("Executando cliente pelo terminal...")
    main()

else:
    print("Não usou terminal, apenas importou módulo.")
