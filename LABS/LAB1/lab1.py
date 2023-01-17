from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
import hashlib

hex_val = 'ff' # 1111 1111

AES_KEY_SIZE = 16
AES_KEY = bytes.fromhex(hex_val) * AES_KEY_SIZE

RC4_KEY_SIZE = 5
RC4_KEY = bytes.fromhex('ff') * RC4_KEY_SIZE


def main():
    AES_ciphertext = encrypt_AES()
    RC4_ciphertext = encrypt_RC4()
    decrypt_RC4(RC4_ciphertext)

def encrypt_AES():

    plaintext = "this is the wireless security lab"
    cipher = AES.new(AES_KEY, AES.MODE_ECB)

    plaintext = plaintext.encode()
    ciphertext = b''

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    print ("AES: ", ciphertext)

    return ciphertext

def encrypt_RC4():

    plaintext = "this is the wireless security lab"
    cipher = ARC4.new(RC4_KEY)

    plaintext = plaintext.encode()

    ciphertext = b''

    ciphertext = cipher.encrypt(plaintext)

    print("RC4: ", ciphertext)

    return ciphertext

def decrypt_AES(ciphertext):

    cipher = AES.new()


def decrypt_RC4(ciphertext):

    S = list(range(256))
    j = 0
    output = []

    
    listObj = list(S)
    #This works but Im using the KEY. How Can we do it with just the key length!?
    #I do not believe it is possible. At least for the scope of this lab

    for i in listObj:
        j = (j + S[i] + RC4_KEY[i % RC4_KEY_SIZE]) % 256
        S[i], S[j] = S[j], S[i]


    i = j = 0
    for char in ciphertext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        output.append(chr(char ^ S[(S[i] + S[j]) % 256]))

    decrypted = ''.join(output)
    print(decrypted)


main()


