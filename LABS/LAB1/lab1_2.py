from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import math
import os

AES_KEY_SIZE = 16
IV = get_random_bytes(AES_KEY_SIZE)
AES_KEY = get_random_bytes(AES_KEY_SIZE)


def main ():
    file_size = os.path.getsize("./mustang.bmp")

    with open("./mustang.bmp", "rb") as file:
        header = file.read(54)
        bytedata = file.read()

    print(AES.block_size)
    encrypt_ECB(header, bytedata)
    encrypt_CBC(header, bytedata)
    encrypt_CFB(header, bytedata)
    encrypt_OFB(header, bytedata)
    encrypt_CTR(header, bytedata)


def encrypt_ECB(header, bytedata):

    plaintext = "abcdabcdabcdabcd"
    cipher = AES.new(AES_KEY, AES.MODE_ECB)

    ciphertext = b''

    ciphertext = cipher.encrypt(pad(bytedata, AES.block_size))

    file_out = open("mustang_ECB.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext)
    file_out.close()

def encrypt_CBC(header, bytedata):

  plaintext = "abcdabcdabcdabcd"
  cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)

  ciphertext = b''

  ciphertext = cipher.encrypt(pad(bytedata, AES.block_size))

  file_out = open("mustang_CBC.bmp", "wb")
  file_out.write(header)
  file_out.write(ciphertext)
  file_out.close()


def encrypt_CFB(header, bytedata):


    plaintext = "abcdabcdabcdabcd"
    cipher = AES.new(AES_KEY, AES.MODE_CFB, IV)

    ciphertext = b''

    ciphertext = cipher.encrypt(pad(bytedata, AES.block_size))

    file_out = open("mustang_CFB.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext)
    file_out.close()


def encrypt_OFB(header, bytedata):


    plaintext = "abcdabcdabcdabcd"
    cipher = AES.new(AES_KEY, AES.MODE_OFB, IV)

    ciphertext = b''

    ciphertext = cipher.encrypt(pad(bytedata, AES.block_size))


    file_out = open("mustang_OFB.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext)
    file_out.close()

def encrypt_CTR(header, bytedata):

    plaintext = "abcdabcdabcdabcd"
    cipher = AES.new(AES_KEY, AES.MODE_CTR)

    ciphertext = b''

    ciphertext = cipher.encrypt(pad(bytedata, AES.block_size))


    file_out = open("mustang_CTR.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext)
    file_out.close()




main()
