from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Cipher import AES
import os
from base64 import b64encode as b64e, b64decode as b64d
class Cryptography:
    def __init__(self):
        pass
    
    def aes_encrypt(self, key, message):
        if type(message) != bytes:
            message = message.encode()

        cipher = AES.new(key if type(key) == bytes else key.encode(), AES.MODE_EAX)
        return {"ciphertext": b64e(cipher.encrypt_and_digest(message)[0]), "nonce": b64e(cipher.nonce)}
    
    def aes_decrypt(self, key: bytes, message, nonce=None):
        if type(message) != bytes:
            message = message.encode()
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(message)
    

    def rsa_encrypt(self, pubkey, text):
        pub = RSA.import_key(pubkey)
        cipher = Cipher_PKCS1_v1_5.new(pub)
        return cipher.encrypt(text.encode() if type(text) == str else text)
    
    def rsa_decrypt(self, privkey, text):
        priv = RSA.import_key(privkey)
        cipher = Cipher_PKCS1_v1_5.new(priv)
        return cipher.decrypt(text.encode() if type(text) == str else text, None)

    def generate_key_pair(self, size = 2048):
        new_pair = RSA.generate(size)
        return (new_pair.public_key().export_key(), new_pair.export_key())
    
    def generate_aes_key(self, length = 32):
        return os.urandom(length)


'''
HOW THINGS SHOULD BE DONE

c = Cryptography()
k = c.generate_aes_key()
a = c.aes_encrypt(k, "testing")
b = c.aes_decrypt(k, b64d(a['ciphertext']), b64d(a['nonce']))
print(b)

PLEASE, FOR THE LOVE OF EVERYTHING, DO NOT CHANGE
ANYTHING IN THE CODE. IT SOMEHOW BREAKS EVERYTIME I
TRY TO DO SOMETHING WITH IT.  

'''