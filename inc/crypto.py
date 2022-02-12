import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5

class Cryptography:
    def __init__(self):
        pass
    
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
