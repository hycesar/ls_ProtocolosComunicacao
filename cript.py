# constantes
import constant

# AES SHA Algorithm
# py -m pip install PyCryptodome
from Crypto.Hash import SHA224
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

# Diffie Hellman Algorithm
# py -m pip install pyDH
import pyDH


def hash(data, nonce=b'0'):
    value = SHA224.new()
    value.update(data + nonce)
    return value.digest()


def encript(key, plaintext):
    cipher = AES.new(key.encode()[:32], AES.MODE_CTR, nonce=key.encode()[33:41])
    return  cipher.encrypt(plaintext)


def decript(key, ciphertext):
    try:
        cipher = AES.new(key.encode()[:32], AES.MODE_CTR, nonce=key.encode()[33:41])
        return cipher.decrypt(ciphertext)
    except:
        print("Incorrect decryption")


def DH_init():
    return pyDH.DiffieHellman()


def DH_send(p):
    return p.gen_public_key()


def DH_recv(p, foreign_pubkey):
    return p.gen_shared_key(foreign_pubkey)
