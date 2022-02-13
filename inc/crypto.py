from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Cipher import AES
import os
class Cryptography:
    def __init__(self):
        pass
    
    def aes_encrypt(self, key, message):
        cipher = AES.new(key if type(key) == bytes else key.encode(), AES.MODE_EAX)
        return (cipher.encrypt_and_digest(message if type(message) == bytes else message.encode())[0], cipher.nonce)
    
    def aes_decrypt(self, key: bytes, message, nonce=None):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(message if type(message) == bytes else message.encode())

    def rsa_encrypt(self, pubkey, text):
        pub = RSA.import_key(pubkey)
        cipher = Cipher_PKCS1_v1_5.new(pub)
        return cipher.encrypt(text.encode() if type(text) == str else text)
    
    def rsa_decrypt(self, privkey, text):
        priv = RSA.import_key(privkey)
        cipher = Cipher_PKCS1_v1_5.new(priv)
        return cipher.decrypt(text.encode() if type(text) == str else text, None)

    def generate_key_pair(self, size = 2048):
        new_pair = RSA.generate(2048)
        return (new_pair.public_key().export_key(), new_pair.export_key())
    
    def generate_aes_key(self, length = 16):
        return os.urandom(length)

