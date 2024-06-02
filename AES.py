#pip3 install base64
#pip3 install pycrypto
import os
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
#Padding, Padding is done to add extra characters so that we get desired length of text
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

#AES MODE = CBC , encryption in AES_CBC mode, requirements = pycrypto 
class CBC:
    def __init__( self, key ):
        self.key = key

    #function for encrypting the message take argument message and iv and returns encrypted text
    def encrypt( self, raw , iv):
        raw = pad(raw)
        cipher = AES.new( self.key, AES.MODE_CBC, iv)
        return base64.b64encode( iv + cipher.encrypt( raw ))

    #function for decrypting the message take argument message and returns encrypted text
    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:]))
#AES MODE = ECB, encryption in AES_ECB mode, requirements = pycrypto 
class ECB:
    def __init__( self, key ):
        self.key = key

    #function for encrypting the message take argument message and returns encrypted text
    def encrypt( self, raw ):
        raw = pad(raw)
        cipher = AES.new( self.key, AES.MODE_ECB )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    #function for decrypting the message take argument message and returns encrypted text
    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_ECB)
        return unpad(cipher.decrypt( enc[16:]))

#AES MODE = OFB, encryption in AES_OFB mode, requirements = pycrypto 
class OFB:
    def __init__( self, key ):
        self.key = key
    #function for encrypting the message take argument message and iv and returns encrypted text
    def encrypt( self, raw ,iv):
        raw = pad(raw)
        cipher = AES.new( self.key, AES.MODE_OFB, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 
    #function for decrypting the message take argument message and returns encrypted text
    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_OFB , iv )
        return unpad(cipher.decrypt( enc[16:]))

#AES MODE = CTR, encryption in AES_CTR mode, requirements = pycrypto 
class CTR:
    def __init__( self, key ):
        self.key = key
    #function for encrypting the message take argument message and iv and returns encrypted text
    def encrypt( self, raw , iv):
        raw = pad(raw)
        ctr = Counter.new(128)
        cipher = AES.new( self.key, AES.MODE_CTR, counter =ctr )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 
    #function for decrypting the message take argument message and returns encrypted text
    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        ctr = Counter.new(128)
        cipher = AES.new(self.key, AES.MODE_CTR, counter = ctr )
        return unpad(cipher.decrypt( enc[16:]))
#generate a new key with given Bloacksize(BS)
def generate_key(BS):
    return os.urandom(BS)
#generate a iv 
def generate_iv():
    return Random.new().read(AES.block_size)
#generate a plain text    
def generate_plaintext():
    return get_random_bytes(16)
#generate a CTR
def generate_CTR():
    return Counter.new(128)

plaintext = generate_plaintext().hex()
key = generate_key(16)
iv = generate_iv()
print('plaintext:',plaintext)
print('iv:',iv.hex())
print('key:',key.hex())
C=CBC(key).encrypt(plaintext,iv)
print('encrypted in CBC:',C)
C=CBC(key).decrypt(C)
print('decrypted in CBC:',C)
C=ECB(key).encrypt(plaintext,iv)
print('encrypted in ECB:',C)
C=ECB(key).decrypt(C)
print('decrypted in ECB:',C)
C=OFB(key).encrypt(plaintext,iv)
print('encrypted in OFB:',C)
C=OFB(key).decrypt(C)
print('decrypted in OFB:',C)
C=CTR(key).encrypt(plaintext,iv)
print('encrypted in CTR:',C)
C=CTR(key).decrypt(C)
print('decrypted in CTR:',C)
print('CTR:', generate_CTR())
