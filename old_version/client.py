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
        self.CONN()

    def CONN(self):
        print("Abrindo socket...")
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print("Usando endereço...{} na porta...{}".format(
            socket.gethostbyname(socket.gethostname()), constant.PORT))
        self.tcp.connect((socket.gethostbyname(
            socket.gethostname()), constant.PORT))

        if self.CONNTEST() and self.CHAPTEST() and self.AESTEST(self.DHKETEST()):
            print('Conexão efetuada com sucesso.\n')

    def CONNTEST(self):
        print("\nMy Three-Way Handshake =P")
        testMsg = b'-Fala, benca!'
        print(testMsg.decode('utf-8'))
        self.tcp.sendall(testMsg)
        testMsg = self.tcp.recv(constant.BUFFSIZE)
        print(testMsg.decode('utf-8'))

        if testMsg.decode('utf-8') == "--Dahle.":
            testMsg = b'-Bora, baratinar :)'
            self.tcp.sendall(testMsg)
            print(testMsg.decode('utf-8'))
            print("\nPing efetuado com sucesso.")
            return True
        return False

    def CHAPTEST(self):
        return self.CHAP(False)

    def CHAP(self, real):
        print("\nChallenge-Handshake Authentication Protocol - CHAP")

        nonce = self.tcp.recv(constant.NONCESIZE)
        print("\nRecebendo nonce para login...{}".format(base64.b85encode(nonce)))

        if real == True:
            msg = input("Insira login>>> ")
        else:
            msg = "12345678901"
        hashmsg = cript.hash(cript.hash(msg.encode()), nonce)
        self.tcp.sendall(hashmsg)
        print("Enviando hash {} de login ...{}".format(
            base64.b85encode(hashmsg), msg))

        nonce = self.tcp.recv(constant.NONCESIZE)
        print("\nRecebendo nonce para senha...{}".format(base64.b85encode(nonce)))

        if real == True:
            msg = getpass("Insira senha>>> ")
        else:
            msg = "123456"
        hashmsg = cript.hash(cript.hash(msg.encode()), nonce)
        self.tcp.sendall(hashmsg)
        print("Enviando hash {} de senha ...{}".format(
            base64.b85encode(hashmsg), msg))

        msg = self.tcp.recv(constant.BUFFSIZE).decode('utf-8')
        if msg == "Olá admin! Bem-vindo, você está autenticado...":
            print(msg)
            return True
        else:
            print("Falha no login e senha. Tente novamente!")
            return False

    def DHKETEST(self):
        return self.DHKE()

    def DHKE(self):
        print("\nDiffie Hellman Key Exchange - DHKE")

        pubkeyServer = self.tcp.recv(constant.BUFFSIZE)
        print("\nRecebendo chave pública do servidor {}.".format(
            base64.b85encode(pubkeyServer)))

        p = cript.DH_init()
        pubkeyClient = cript.DH_send(p)
        self.tcp.sendall(pubkeyClient.to_bytes(constant.DIFFSIZE, 'big'))
        print("\nEnviando chave pública do cliente {}.".format(
            base64.b85encode(pubkeyClient.to_bytes(constant.DIFFSIZE, 'big'))))

        sharekey = cript.DH_recv(
            p, int.from_bytes(pubkeyServer, byteorder='big'))
        print("\nCalculando chave compartilhada... {}".format(
            base64.b85encode(sharekey.encode())))

        nonce = self.tcp.recv(constant.NONCESIZE)
        print("\nRecebendo nonce...{}".format(base64.b85encode(nonce)))

        clientResponse = cript.hash(sharekey.encode(), nonce)
        self.tcp.sendall(clientResponse)
        print("\nEnviando resposta...{}".format(
            base64.b85encode(clientResponse)))

        serverResponse = self.tcp.recv(constant.BUFFSIZE).decode('utf-8')
        if "Compartilhamento de chaves concluído com sucesso." == serverResponse:
            print(serverResponse)
            return sharekey

        else:
            print(serverResponse)
            time.sleep(cript.randint(5, 10))
            return False

    def AESTEST(self, sharekey):
        print("\nMy Three-Way Handshake - AES Version - CLIENTE")
        msg = b"-Bote feh, Vei."
        print("\n", msg)
        ciphertext = cript.encript(sharekey, msg)
        print("Enviando mensagem ao servidor {}.".format(ciphertext))
        self.tcp.sendall(ciphertext)

        msg = cript.decript(sharekey, self.tcp.recv(constant.BUFFSIZE))
        print("\nMensagem recebida: {}".format(msg.decode('utf-8')))
        if msg == b"--Deeeeeu a bixiga!":

            msg = b"-Mermao, muito donzelo."
            print("\n", msg)
            ciphertext = cript.encript(sharekey, msg)
            print("Enviando mensagem ao servidor{}.".format(ciphertext))
            self.tcp.sendall(ciphertext)

            print("\nComunicação segura por AES efetuada com sucesso.")
            return True
        return False

    def insert(self):  # insere eleitores no banco de dados
        # self.tcp.send(cript.encript(1))
        self.tcp.sendall(b'1')
        print('Digite seu CPF\n')
        cpf = input()
        cpf = cript.hash(cpf.encode())
        self.tcp.sendall(cpf.encode('utf-8'))
        print('Digite uma senha\n')
        senha = input()
        senha = cript.hash(senha.encode())
        self.tcp.sendall(senha.encode('utf-8'))
        print(self.tcp.recv(1024).decode('utf-8'))

    def vote(self):
        self.tcp.sendall(b'2')
        print('Digite seu CPF\n')
        cpf = input()
        cpf = cript.hash(cpf.encode())
        self.tcp.sendall(cpf.encode('utf-8'))
        print('Digite sua senha\n')
        senha = input()
        senha = cript.hash(senha.encode())
        self.tcp.sendall(senha.encode('utf-8'))
        votou = self.tcp.recv(1024)
        # votou = cript.decript(votou)
        if(votou == False):
            print('Usuario ja votou/nao cadastrado\n')

        else:
            print('Digite seu voto\n')
            #voto = input()
            # voto = cript.encript(voto)
            # self.tcp.sendall(voto.encode('utf-8'))
            # print('FIM')
            self.tcp.close()

    def close(self):
        print("Fim da execução...")
        self.tcp.close()

    def run(self):
        run = True
        executions = 0
        while(run):
            print(executions)
            msg = input("Insira comando>>> ")

            if msg == "_votar":
                self.vote

            elif msg == "_inserir":
                self.insert

            elif msg == "Sair":
                run = False
                print("Enviando comando ao servidor...")
                self.tcp.sendall(msg.encode())

            else:
                print("Enviando comando ao servidor...")
                self.tcp.sendall(msg.encode())

        


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Criando instância do cliente...")
    s = Client()
    s.run()
    s.close()


if __name__ == "__main__":
    print("Executando cliente pelo terminal...")
    main()

else:
    print("Não usou terminal, apenas importou módulo.")
