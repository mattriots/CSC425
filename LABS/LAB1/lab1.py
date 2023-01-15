from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
import hashlib
KEY_SIZE = 16
KEY = get_random_bytes(KEY_SIZE)

def encrypt_AES():

    cipher = AES.new(KEY, AES.MODE_ECB)
    plaintext = "this is the wireless security lab"

    ciphertext = cipher.encrypt(plaintext)
    ciphertext.encode("hex")

