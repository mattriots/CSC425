from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import math
import os

AES_KEY_SIZE = 16
IV = get_random_bytes(AES_KEY_SIZE)
AES_KEY = get_random_bytes(AES_KEY_SIZE)
NONCE = 0


def main():
    file_size = os.path.getsize("./mustang.bmp")

    with open("./mustang.bmp", "rb") as file:
        header = file.read(54)
        bytedata = file.read()

    ciphertext_ECB = encrypt_ECB(header, bytedata)
    ciphertext_CBC = encrypt_CBC(header, bytedata)
    ciphertext_CFB = encrypt_CFB(header, bytedata)
    ciphertext_OFB = encrypt_OFB(header, bytedata)
    ciphertext_CTR = encrypt_CTR(header, bytedata)

    decrypt_All(ciphertext_ECB, ciphertext_CBC, ciphertext_CFB,
                ciphertext_OFB, ciphertext_CTR)


def encrypt_ECB(header, bytedata):

    plaintext = "abcdabcdabcdabcd"
    plaintext = plaintext.encode()

    cipher = AES.new(AES_KEY, AES.MODE_ECB)

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher.encrypt(pad(bytedata, AES.block_size))
    ciphertext_string = cipher.encrypt(pad(plaintext, AES.block_size))

    file_out = open("mustang_ECB.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string


def encrypt_CBC(header, bytedata):

    plaintext = "abcdabcdabcdabcd"

    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
    plaintext = plaintext.encode()

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher.encrypt(pad(bytedata, AES.block_size))
    ciphertext_string = cipher.encrypt(pad((plaintext), AES.block_size))

    file_out = open("mustang_CBC.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string


def encrypt_CFB(header, bytedata):

    plaintext = "abcdabcdabcdabcd"
    plaintext = plaintext.encode()

    cipher = AES.new(AES_KEY, AES.MODE_CFB, IV)

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher.encrypt(pad(bytedata, AES.block_size))
    ciphertext_string = cipher.encrypt(pad(plaintext, AES.block_size))

    file_out = open("mustang_CFB.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string


def encrypt_OFB(header, bytedata):

    plaintext = "abcdabcdabcdabcd"
    plaintext = plaintext.encode()

    cipher = AES.new(AES_KEY, AES.MODE_OFB, IV)

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher.encrypt(pad(bytedata, AES.block_size))
    ciphertext_string = cipher.encrypt(pad(plaintext, AES.block_size))

    file_out = open("mustang_OFB.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string


def encrypt_CTR(header, bytedata):

    plaintext = "abcdabcdabcdabcd"
    plaintext = plaintext.encode()

    cipher = AES.new(AES_KEY, AES.MODE_CTR)

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher.encrypt(bytedata)
    ciphertext_string = cipher.encrypt(plaintext)

    file_out = open("mustang_CTR.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string

# Work on this


def decrypt_All(ciphertext_ECB, ciphertext_CBC, ciphertext_CFB,
                ciphertext_OFB, ciphertext_CTR):

    cipher_ECB = AES.new(AES_KEY, AES.MODE_ECB)
    cipher_CBC = AES.new(AES_KEY, AES.MODE_CBC, IV)
    cipher_CFB = AES.new(AES_KEY, AES.MODE_CFB, IV)
    cipher_OFB = AES.new(AES_KEY, AES.MODE_OFB, IV)

    cipher_CTR = AES.new(AES_KEY, AES.MODE_CTR)

    plain_ECB = cipher_ECB.decrypt(ciphertext_ECB)

    # plain_CBC = cipher_CBC.decrypt(ciphertext_CBC)
    # unpad(plain_CBC, AES.block_size)
    # plain_CBC = plain_CBC.decode()

    plain_CFB = cipher_CFB.decrypt(ciphertext_CFB)
    plain_OFB = cipher_OFB.decrypt(ciphertext_OFB)

    plain_CTR = cipher_CTR.decrypt(ciphertext_CTR)

    print("ECB: ", plain_ECB)
    # print("CBC: ", plain_CBC)
    print("CFB: ", plain_CFB)
    print("OFB: ", plain_OFB)
    print("CTR: ", plain_CTR)


main()
