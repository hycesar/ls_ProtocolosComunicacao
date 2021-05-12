# terminal
import os

# constants
import constant

# tcp
import socket

# crypto suport
import cript

# bd
import data

# intrusion
import time

# decode
import base64


class Server:
    def __init__(self):
        self.BD()
        self.CONN()

    def BD(self):
        print("Criando estrutura de dados...")
        self.__mesario = data.Mesarios()
        self.__eleitor = data.Eleitores()
        self.__candidato = data.Candidatos()

    def CONN(self):
        print("Abrindo socket...")
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print("Usando endereço...{} na porta...{}".format(
            socket.gethostbyname(socket.gethostname()), constant.PORT))
        self.tcp.bind((socket.gethostbyname(
            socket.gethostname()), constant.PORT))
        self.tcp.listen(constant.QUEUESIZE)

        if self.CONNTEST() and self.CHAPTEST() and self.AESTEST(self.DHKETEST()):
            print('Conexão efetuada com sucesso.')

        else:
            return 0

    def CONNTEST(self):
        print("\nAguardando conexão...")
        self.conn, self.addr = self.tcp.accept()
        msg = self.conn.recv(constant.BUFFSIZE).decode('utf-8')
        print("Mensagem recebida: {}".format(msg))

        if msg == '-Fala, benca!':
            self.conn.sendall(b'--Dahle.')
            msg = self.conn.recv(constant.BUFFSIZE).decode('utf-8')

            if msg == '-Bora, baratinar :)':
                print("\nPing efetuado com sucesso!")
                return True
        return False

    def CHAPTEST(self):
        return self.CHAP()

    def CHAP(self):
        print("\nChallenge-Handshake Authentication Protocol - CHAP")

        nonce = cript.get_random_bytes(constant.NONCESIZE)
        self.conn.sendall(nonce)
        print("\nEnviando nonce para login...{}".format(base64.b85encode(nonce)))

        clientResponse = self.conn.recv(constant.BUFFSIZE)
        print("Recebendo resposta...{}".format(
            base64.b85encode(clientResponse)))

        indice = self.__mesario.search(clientResponse, nonce)

        nonce = cript.get_random_bytes(constant.NONCESIZE)
        self.conn.sendall(nonce)
        print("\nEnviando novo nonce para senha...{}".format(
            base64.b85encode(nonce)))

        clientResponse = self.conn.recv(constant.BUFFSIZE)
        print("Recebendo resposta...{}".format(
            base64.b85encode(clientResponse)))

        if indice >= 0:

            if clientResponse == cript.hash(self.__mesario.pswd(indice), nonce):
                msg = "Olá " + \
                    self.__mesario.name(indice) + \
                    "! Bem-vindo, você está autenticado..."
                self.conn.sendall(msg.encode())
                print(msg)
                return True

        else:
            msg = "ERRO: Falha na autenticação! Aguardando tempo aleatório."
            print(msg)
            self.conn.sendall(msg.encode())
            time.sleep(cript.randint(5, 10))
            return False

    def DHKETEST(self):
        return self.DHKE()

    def DHKE(self):
        print("\nDiffie Hellman Key Exchange - DHKE")

        p = cript.DH_init()
        pubkeyServer = cript.DH_send(p)
        self.conn.sendall(pubkeyServer.to_bytes(constant.DIFFSIZE, 'big'))
        print("\nEnviando chave pública do servidor {}.".format(
            base64.b85encode(pubkeyServer.to_bytes(constant.DIFFSIZE, 'big'))))

        pubkeyClient = self.conn.recv(constant.BUFFSIZE)
        print("\nRecebendo chave pública do cliente {}".format(
            base64.b85encode(pubkeyClient)))

        sharekey = cript.DH_recv(
            p, int.from_bytes(pubkeyClient, byteorder='big'))
        print("\nCalculando chave compartilhada...{}".format(
            base64.b85encode(sharekey.encode())))

        nonce = cript.get_random_bytes(constant.NONCESIZE)
        self.conn.sendall(nonce)
        print("\nEnviando nonce...{}".format(base64.b85encode(nonce)))

        clientResponse = self.conn.recv(constant.BUFFSIZE)
        print("\nRecebendo resposta...{}".format(
            base64.b85encode(clientResponse)))

        if cript.hash(sharekey.encode(), nonce) == clientResponse:
            serverResponse = "Compartilhamento de chaves concluído com sucesso."
            self.conn.sendall(serverResponse.encode())
            return sharekey

        else:
            serverResponse = "ERRO: Falha na troca de chaves! Aguarde tempo aleatório"
            print(serverResponse)
            self.conn.sendall(serverResponse.encode())
            time.sleep(cript.randint(5, 10))
            return False

    def AESTEST(self, sharekey):
        print("\nMy Three-Way Handshake - AES Version - SERVER")
        ciphertext = self.conn.recv(constant.BUFFSIZE)
        msg = cript.decript(sharekey, ciphertext)
        print("\nMensagem recebida: {}".format(msg.decode('utf-8')))

        if msg == b"-Bote feh, Vei.":
            ciphertext = cript.encript(sharekey, b"--Deeeeeu a bixiga!")
            print("\nEnviando mensagem ao cliente {}.".format(ciphertext))
            self.conn.sendall(ciphertext)

            msg = cript.decript(sharekey, self.conn.recv(constant.BUFFSIZE))
            print("\nMensagem recebida: {}".format(msg.decode('utf-8')))
            if msg == b"-Mermao, muito donzelo.":

                print("\nComunicação segura por AES efetuada com sucesso.")
                return True
        return False

    def REP(self, key):
        for k in range(0, len(self.__eleitor.lista)):
            self.conn.sendall(cript.encript(key, "Candidato"))
            self.conn.sendall(cript.encript(
                key, self.__eleitor.lista[k][0]))
            self.conn.sendall(cript.encript(key, " = "))
            self.conn.sendall(cript.encript(
                key, self.__eleitor.lista[k][1]))
            self.conn.sendall(cript.encript(key, "TOTAL:"))
            self.conn.sendall(cript.encript(
                key, self.__eleitor.lista[k][2]))
            self.conn.sendall(cript.encript(key, "Votos"))
        self.conn.sendall(cript.encript(key, 'FIM'))

    def SHUT(self):
        print("Finalizando servidor graciosamente...")
        self.conn.close()

    def run(self):
        run = True
        executions = 0
        while(run):

            print(executions)
            print("Aguardando conexão...")
            #self.conn, self.addr = self.tcp.accept()

            msg = self.conn.recv(constant.BUFFSIZE).decode('utf-8')
            print("Mensagem recebida: {}".format(msg))

            if msg == "Autenticar":
                autenticado = self.CHAP()

                while(autenticado):

                    if msg == "Cadastrar Eleitor":
                        print("Cadastrando eleitor...")  # fazer

                    elif msg == "Cadastrar Candidato":
                        print("Cadastrando candidato...")  # fazer

                    elif msg == "Parcial":
                        print("Enviando relatório...")
                        self.REP(self.DHKE())

                    if msg == "Sair":
                        print("Administrador saindo...")
                        autenticado = 0

                    else:
                        print("ERRO: Mensagem inesperada! Aguardando tempo aleatório")
                        time.sleep(cript.randint(0, 5))
                        return 0

            elif msg == "Votar":
                print("Iniciando processo de votação, com a troca de chaves...")
                key = self.DHKE()

                cpf = self.conn.recv(constant.BUFFSIZE)
                password = self.conn.recv(constant.BUFFSIZE)

                if self.__eleitor.vote(cpf, password) == True:
                    self.conn.sendall(cript.encript(key, False))

                else:
                    self.conn.sendall(cript.encript(key, True))
                    voto = self.conn.recv(constant.BUFFSIZE)
                    voto = cript.decript(key, voto)
                    self.__candidato.regsvote(voto)

                if msg == "Candidato":
                    nome = self.conn.recv(constant.BUFFSIZE)
                    nome = cript.decript(key, nome)
                    numero = self.conn.rect(constant.BUFFSIZE)
                    numero = cript.decript(key, numero)
                    valido = self.__candidato.check(nome, numero)

                    if valido == False:
                        self.__candidato.insert(nome, numero, 0)
                        self.conn.sendall(b'Candidato Cadastrado')

                    else:
                        self.conn.sendall(b'Candidato ja existe')

                        self.conn.sendall(cript.encript(key, data))
                        self.conn.close()
                        #self.__eleitor.insert(cpf, password, False)
                        #self.conn.sendall(b'Cadastrado com sucesso')

                    # else:
                        #self.conn.sendall(b'ERRO: USUARIO JA CADASTRADO')

            elif msg == "Sair":
                run = False

            else:
                print("Mensagem {} inesperada".format(msg))

            executions += 1

        self.SHUT()


def main():
    os.system('cls' if os.name == 'nt' else 'clear')

    print("Criando instância de servidor...")
    s = Server()
    s.run()


if __name__ == "__main__":
    print("Executando servidor pelo terminal...")
    main()

else:
    print("Não usou terminal, apenas importou módulo.")
