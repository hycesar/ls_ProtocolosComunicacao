# crypto suport
import cript

# enum
from enum import Enum


class eleitorAttrib(Enum):
    cpf = 0
    password = 1
    vote = 2


class candidatoAttrib(Enum):
    nome = 0
    numero = 1
    votes = 2


class mesarioAttrib(Enum):
    nome = 0
    hashcpf = 1
    hashpswd = 2


class Eleitores:
    def __init__(self):
        self.lista = []
        self.users = 0

    def insert(self, cpf, password, vote):
        self.lista.append((cpf, password, vote))
        self.users += 1

    def search(self, cpf):
        existe = False
        for k in range(0, len(self.lista)):

            if self.lista[k][eleitorAttrib.cpf.value] == cpf:
                existe = True

        return existe

    def vote(self, cpf, password):
        existe = False
        for k in range(0, len(self.lista)):

            if self.lista[k][eleitorAttrib.cpf.value] == cpf:

                if self.lista[k][eleitorAttrib.password.value] == password:

                    if self.lista[k][eleitorAttrib.vote.value] == False:
                        existe = True

        return existe


class Candidatos:
    def __init__(self):
        self.lista = []

    def insert(self, nome, numero, quant):
        self.lista.append((nome, numero, quant))

    def check(self, nome, numero):
        existe = False
        for k in range(0, len(self.lista)):

            if self.lista[k][candidatoAttrib.nome.value] == nome:

                if self.lista[k][candidatoAttrib.numero.value] == numero:
                    existe = True

        return existe

    def regsvote(self, numero):
        for k in range(0, len(self.lista)):

            if self.lista[k][candidatoAttrib.numero.value] == numero:
                self.lista[k][candidatoAttrib.votes.value] += 1


class Mesarios:
    def __init__(self):
        # Adicionar o primeiro administrador com uma senha padrão
        self.lista = []
        self.insert("admin", cript.hash(b'12345678901'), cript.hash(b'123456'))

    def insert(self, nm, hashcpf, hashpswd):
        self.lista.append((nm, hashcpf, hashpswd))

    def search(self, response, nonce):
        mesario = -1
        for i in range(0, len(self.lista)):
            resp = cript.hash(
                self.lista[i][mesarioAttrib.hashcpf.value], nonce)

            if resp == response:
                mesario = i

        return mesario

    def pswd(self, i):
        return self.lista[i][mesarioAttrib.hashpswd.value]

    def name(self, i):
        return self.lista[i][mesarioAttrib.nome.value]
