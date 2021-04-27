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
        print(
            f"{constant.bcolors.HEADER}\nInfo: Criando instância de servidor.{constant.bcolors.ENDC}")
        self.database()
        self.connection()

    def database(self):
        print(
            f"{constant.bcolors.HEADER}\nInfo: Criando estrutura de dados.{constant.bcolors.ENDC}")
        self.__mesario = data.Mesarios()
        self.__eleitor = data.Eleitores()
        self.__candidato = data.Candidatos()

    def connection(self):
        print(
            f"{constant.bcolors.HEADER}\nInfo: Criando socket.{constant.bcolors.ENDC}")
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print("Usando endereço...{} na porta...{}".format(
            socket.gethostbyname(socket.gethostname()), constant.PORT))
        self.tcp.bind((socket.gethostbyname(
            socket.gethostname()), constant.PORT))
        self.tcp.listen(constant.QUEUESIZE)

        print(
            f"{constant.bcolors.FAIL}Iniciando testes iniciais entre cliente-servidor...{constant.bcolors.ENDC}")
        if self.connection_test() and self.chap_test() and self.aes_test(self.dhke_test()):
            print(
                f"{constant.bcolors.FAIL}Todos os testes iniciais, entre cliente e servidor, efetuados com sucesso!\n{constant.bcolors.ENDC}")
            return True

        else:
            return False

    def connection_test(self):
        print(f"{constant.bcolors.HEADER}\nInfo: My Three-Way Handshake...aguardando...{constant.bcolors.ENDC}")
        self.conn, self.addr = self.tcp.accept()

        msg = self.conn.recv(constant.BUFFSIZE).decode('utf-8')
        print(f"{constant.bcolors.OKGREEN}Mensagem recebida:",
              msg, f"{constant.bcolors.ENDC}")
        if msg == '-Fala, benca!':

            msg = "--Dahle."
            self.conn.sendall(msg.encode())
            print(f"{constant.bcolors.WARNING}Enviando mensagem:",
                  msg, f"{constant.bcolors.ENDC}")

            msg = self.conn.recv(constant.BUFFSIZE).decode('utf-8')
            print(f"{constant.bcolors.OKGREEN}Mensagem recebida:",
                  msg, f"{constant.bcolors.ENDC}")
            if msg == "-Bora, baratinar :)":

                print("Protocolo efetuado com sucesso!")
                time.sleep(cript.randint(3, 6))
                return True
            print("\nErro: Falha no protocolo.")
            time.sleep(cript.randint(3, 6))
            return False

    def chap_test(self):
        return self.chap()

    def chap(self):
        print(f"{constant.bcolors.HEADER}\nChallenge-Handshake Authentication Protocol - CHAP - Server{constant.bcolors.ENDC}")

        nonce = cript.get_random_bytes(constant.NONCESIZE)
        self.conn.sendall(nonce)
        print(f"{constant.bcolors.WARNING}Enviando nonce para login...",
              base64.b85encode(nonce), f"{constant.bcolors.ENDC}")

        hashmsg = self.conn.recv(constant.BUFFSIZE)
        print(f"{constant.bcolors.OKGREEN}Recebendo resposta...",
              base64.b85encode(hashmsg), f"{constant.bcolors.ENDC}")

        indice = self.__mesario.search(hashmsg, nonce)

        nonce = cript.get_random_bytes(constant.NONCESIZE)
        self.conn.sendall(nonce)
        print(f"{constant.bcolors.WARNING}Enviando novo nonce para senha...",
              base64.b85encode(nonce), f"{constant.bcolors.ENDC}")

        hashmsg = self.conn.recv(constant.BUFFSIZE)
        print(f"{constant.bcolors.OKGREEN}Recebendo resposta...",
              base64.b85encode(hashmsg), f"{constant.bcolors.ENDC}")

        if indice >= 0:

            if hashmsg == cript.hash(self.__mesario.pswd(indice), nonce):
                msg = "Olá " + \
                    self.__mesario.name(indice) + \
                    "! Bem-vindo, você está autenticado!"
                self.conn.sendall(msg.encode())
                print(msg)
                time.sleep(cript.randint(3, 6))
                return True

        else:
            msg = "ERRO: Falha na autenticação! Aguardando tempo aleatório."
            print(msg)
            self.conn.sendall(msg.encode())
            time.sleep(cript.randint(3, 6))
            return False

    def dhke_test(self):
        return self.dhke()

    def dhke(self):
        print(
            f"{constant.bcolors.HEADER}\nDiffie Hellman Key Exchange - DHKE - Server{constant.bcolors.ENDC}")

        p = cript.DH_init()
        pubkeyServer = cript.DH_send(p)
        self.conn.sendall(pubkeyServer.to_bytes(constant.DIFFSIZE, 'big'))
        print(f"{constant.bcolors.WARNING}Enviando chave pública do servidor.",
              base64.b85encode(pubkeyServer.to_bytes(constant.DIFFSIZE, 'big')), f"{constant.bcolors.ENDC}")

        pubkeyClient = self.conn.recv(constant.BUFFSIZE)
        print(f"{constant.bcolors.OKGREEN}Recebendo chave pública do cliente",
              base64.b85encode(pubkeyClient), f"{constant.bcolors.ENDC}")

        sharedkey = cript.DH_recv(
            p, int.from_bytes(pubkeyClient, byteorder='big'))
        print("Calculando chave compartilhada...{}\n".format(
            base64.b85encode(sharedkey.encode())))

        nonce = cript.get_random_bytes(constant.NONCESIZE)
        self.conn.sendall(nonce)
        print(f"{constant.bcolors.WARNING}Enviando nonce...",
              base64.b85encode(nonce), f"{constant.bcolors.ENDC}")

        hashmsg = self.conn.recv(constant.BUFFSIZE)
        print(f"{constant.bcolors.OKGREEN}Recebendo hash...",
              base64.b85encode(hashmsg), f"{constant.bcolors.ENDC}")

        if cript.hash(sharedkey.encode(), nonce) == hashmsg:
            serverResponse = "Compartilhamento de chaves concluído com sucesso."
            print(serverResponse)
            self.conn.sendall(serverResponse.encode())
            time.sleep(cript.randint(3, 6))
            return sharedkey

        else:
            serverResponse = "ERRO: Falha na troca de chaves! Aguarde tempo aleatório"
            print(serverResponse)
            self.conn.sendall(serverResponse.encode())
            time.sleep(cript.randint(3, 6))
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
        print(f"{constant.bcolors.HEADER}\nMy Three-Way Handshake - AES Version - Server{constant.bcolors.ENDC}")

        msg = self.aes_decrypt(self.conn.recv(constant.BUFFSIZE), sharedkey)

        if msg == "-Bote feh, Vei.":

            self.conn.sendall(self.aes_crypt("--Deeeeeu a bixiga!", sharedkey))

            msg = self.aes_decrypt(self.conn.recv(
                constant.BUFFSIZE), sharedkey)

            if msg == "-Mermao, muito donzelo.":

                print("Comunicação segura por AES efetuada com sucesso.")
                time.sleep(cript.randint(3, 6))
                return True
        time.sleep(cript.randint(3, 6))
        return False

    def candidate_add(self, sharedkey):
        print(
            f"{constant.bcolors.HEADER}Cadastrando candidato...{constant.bcolors.ENDC}")

        sucess = False
        while not sucess:
            numero = self.aes_decrypt(
                self.conn.recv(constant.BUFFSIZE), sharedkey)
            if self.__candidato.check(numero):
                self.conn.sendall(self.aes_crypt(
                    "Falha: Numero já cadastrado.", sharedkey))
            else:
                self.conn.sendall(self.aes_crypt("Sucesso", sharedkey))
                sucess = True

        nome = self.aes_decrypt(self.conn.recv(constant.BUFFSIZE), sharedkey)
        if self.__candidato.insert(numero, nome):
            self.conn.sendall(self.aes_crypt(
                "Candidato cadastrado com sucesso.", sharedkey))

    def voter_add(self, sharedkey):
        print(f"{constant.bcolors.HEADER}Cadastrando eleitor...{constant.bcolors.ENDC}")
        
        sucess = False
        while not sucess:
            cpf = self.aes_decrypt(
                self.conn.recv(constant.BUFFSIZE), sharedkey)
            if self.__eleitor.check(cpf):
                self.conn.sendall(self.aes_crypt(
                    "Falha: CPF já cadastrado.", sharedkey))
            else:
                self.conn.sendall(self.aes_crypt("Sucesso", sharedkey))
                sucess = True

        nome = self.aes_decrypt(self.conn.recv(constant.BUFFSIZE), sharedkey)
        pswd = self.aes_decrypt(self.conn.recv(constant.BUFFSIZE), sharedkey)       
        if self.__eleitor.insert(cpf, nome, pswd):
            self.conn.sendall(self.aes_crypt(
                "Candidato cadastrado com sucesso.", sharedkey))
        else:
            self.conn.sendall(self.aes_crypt(
                "Falha no cadastro do eleitor.", sharedkey))

    def logoff(self):
        print(f"{constant.bcolors.HEADER}Logoff do Administrador...{constant.bcolors.ENDC}")
        return False

    def vote(self, sharedkey):
        print(
            f"{constant.bcolors.HEADER}Iniciando votação...{constant.bcolors.ENDC}")

        cpf = self.aes_decrypt(self.conn.recv(constant.BUFFSIZE), sharedkey)
        pswd = self.aes_decrypt(self.conn.recv(constant.BUFFSIZE), sharedkey)

        if not self.__eleitor.can_vote(cpf, pswd):
            self.conn.sendall(self.aes_crypt("Falha de permissão: login e/ou senha errados, eleitor não cadastrado ou já votou.", sharedkey))
        else:
            self.conn.sendall(self.aes_crypt("Permitido", sharedkey))
            voto = self.aes_decrypt(self.conn.recv(constant.BUFFSIZE), sharedkey)
            self.__candidato.regsvote(voto)

    def report(self):
        print("Enviando relatório...")
        for i in range(0, len(self.__candidato.lista)):
            self.conn.sendall(b'Candidato ')
            self.conn.sendall(self.__candidato.lista[i][1].encode())
            self.conn.sendall(b'=> Votos: ')
            self.conn.sendall(str(self.__candidato.lista[i][2]).encode())
        time.sleep(cript.randint(1, 2)) #sincroniscmo
        self.conn.sendall(b'FIM')

    def shut(self):
        print("Finalizando execução do servidor graciosamente...")
        self.conn.close()

    def run(self):
        run = True
        loops = 0
        while(run):
            print(f"{constant.bcolors.OKGREEN}\nLoop:",
                  loops, "Aguardando mensagem...", f"{constant.bcolors.ENDC}")
            #self.conn, self.addr = self.tcp.accept()

            msg = self.conn.recv(constant.BUFFSIZE).decode('utf-8')
            print("Mensagem recebida: {}".format(msg))

            if msg == "Autenticar":
                autenticado = self.chap()

            elif msg == "Votar":
                self.vote(self.dhke())

            elif msg == "Relatório":
                self.report()

            elif msg == "Sair":
                run = False

            else:
                if autenticado:
                    if msg == "Cadastrar Candidato":
                        self.candidate_add(self.dhke())

                    elif msg == "Cadastrar Eleitor":
                        self.voter_add(self.dhke())

                    elif msg == "Logoff":
                        autenticado = self.logoff()

                    else:
                        print("ERRO: Mensagem inesperada {}! Aguardando tempo aleatório".format(msg))
                        time.sleep(cript.randint(3, 6))
                else:
                    print("ERRO: Mensagem inesperada {}! Aguardando tempo aleatório".format(msg))
                    time.sleep(cript.randint(3, 6))
                    
            loops += 1

        self.shut()


def main():
    os.system('cls' if os.name == 'nt' else 'clear')

    s = Server()
    s.run()


if __name__ == "__main__":
    print("Executando servidor pelo terminal...")
    main()

else:
    print("Não usou terminal, apenas importou módulo.")
