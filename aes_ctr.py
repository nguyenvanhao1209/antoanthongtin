import binascii
import os
from hashlib import md5
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
def bytes_to_int(bytes):
    result = 0

    for b in bytes:
        result = result * 256 + int(b)

    return result
class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()
    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        ctr = Counter.new(nbits=128, little_endian=True, initial_value=bytes_to_int(iv))
        self.cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return b64encode(iv + self.cipher.encrypt(data.encode('utf-8')))
    def decrypt(self, data):
        raw = b64decode(data)[:AES.block_size]
        ctr = Counter.new(nbits=128, little_endian=True, initial_value=bytes_to_int(raw))
        self.cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return self.cipher.decrypt(b64decode(data)[AES.block_size:])
if __name__ == '__main__':
    print('ENCRYPTION')
    msg = input('Message...: ')
    pwd = input('Key..: ')
    print('Ciphertext:', AESCipher(pwd).encrypt(msg).decode('utf-8'))

    print('\nDECRYPTION')
    cte = input('Ciphertext: ')
    pwd = input('Key..: ')
    print('Message...:', AESCipher(pwd).decrypt(cte).decode('utf-8'))