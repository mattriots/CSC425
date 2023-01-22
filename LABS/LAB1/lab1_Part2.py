from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
import urllib.parse

AES_KEY_SIZE = 16
IV = get_random_bytes(AES_KEY_SIZE)
AES_KEY = get_random_bytes(AES_KEY_SIZE)
NONCE = get_random_bytes(8)
Countf = Counter.new(64, NONCE)

def main():

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

    plaintext = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop"
    plaintext = plaintext.encode()

    cipher_pic = AES.new(AES_KEY, AES.MODE_ECB)
    cipher_string = AES.new(AES_KEY, AES.MODE_ECB)

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher_pic.encrypt(pad(bytedata, AES.block_size))
    ciphertext_string = cipher_string.encrypt(pad(plaintext, AES.block_size))

    file_out = open("mustang_ECB.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string


def encrypt_CBC(header, bytedata):

    plaintext = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop"
    cipher_pic = AES.new(AES_KEY, AES.MODE_CBC, IV)
    cipher_string = AES.new(AES_KEY, AES.MODE_CBC, IV)
   
    plaintext = plaintext.encode()

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher_pic.encrypt(pad(bytedata, AES.block_size))
    ciphertext_string = cipher_string.encrypt(pad(plaintext, AES.block_size))

    file_out = open("mustang_CBC.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string


def encrypt_CFB(header, bytedata):

    plaintext = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop"
    plaintext = plaintext.encode()

    cipher_pic = AES.new(AES_KEY, AES.MODE_CFB, IV)
    cipher_string = AES.new(AES_KEY, AES.MODE_CFB, IV)

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher_pic.encrypt(bytedata)
    ciphertext_string = cipher_string.encrypt(plaintext)

    file_out = open("mustang_CFB.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string


def encrypt_OFB(header, bytedata):

    plaintext = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop"
    plaintext = plaintext.encode()

    cipher_pic = AES.new(AES_KEY, AES.MODE_OFB, IV)
    cipher_string = AES.new(AES_KEY, AES.MODE_OFB, IV)

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher_pic.encrypt(bytedata)
    ciphertext_string = cipher_string.encrypt(plaintext)

    file_out = open("mustang_OFB.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string


def encrypt_CTR(header, bytedata):

    plaintext = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop"
    plaintext = plaintext.encode()

    cipher_pic = AES.new(AES_KEY, AES.MODE_CTR, counter=Countf)
    cipher_string = AES.new(AES_KEY, AES.MODE_CTR, counter=Countf)

    ciphertext_pic = b''
    ciphertext_string = b''

    ciphertext_pic = cipher_pic.encrypt(bytedata)
    ciphertext_string = cipher_string.encrypt(plaintext)

    file_out = open("mustang_CTR.bmp", "wb")
    file_out.write(header)
    file_out.write(ciphertext_pic)
    file_out.close()

    return ciphertext_string

# Work on this

def modifyBit(ciphertext):
    ciplist = bytearray(ciphertext)

    ciplist[3] = ((ciplist[0]) ^ ord('f') ^ ord('d'))
    # ciplist[4] = ((ciplist[4]) & ord('a'))

    return bytes(ciplist)


def decrypt_All(ciphertext_ECB, ciphertext_CBC, ciphertext_CFB,
                ciphertext_OFB, ciphertext_CTR):

    # Alter Bit then DECRYPT ECB

    ciphertext_ECB_Mod = modifyBit(ciphertext_ECB)  
    cipher_ECB = AES.new(AES_KEY, AES.MODE_ECB)
    plain_ECB = cipher_ECB.decrypt(ciphertext_ECB_Mod)
    unpad(plain_ECB, AES.block_size)
    plain_ECB = urllib.parse.unquote(plain_ECB)
    # plain_ECB = plain_ECB.decode()
    print("ECB: ", plain_ECB)

    # Alter Bit then DECRYPT CBC
    ciphertext_CBC_Mod = modifyBit(ciphertext_CBC)
    cipher_CBC = AES.new(AES_KEY, AES.MODE_CBC, IV)
    plain_CBC = cipher_CBC.decrypt(ciphertext_CBC_Mod)
    # unpad(plain_CBC, AES.block_size)
    plain_CBC = urllib.parse.unquote(plain_CBC)
    print("CBC: ", plain_CBC)

    # Alter Bit then DECRYPT CFB
    ciphertext_CFB_Mod = modifyBit(ciphertext_CFB)
    cipher_CFB = AES.new(AES_KEY, AES.MODE_CFB, IV)
    plain_CFB = cipher_CFB.decrypt(ciphertext_CFB_Mod)
    # plain_CFB = plain_CFB.decode()
    plain_CFB = urllib.parse.unquote(plain_CFB)
    print("CFB: ", plain_CFB)

    # Alter Bit then DECRYPT OFB
    ciphertext_OFB_Mod = modifyBit(ciphertext_OFB)
    cipher_OFB = AES.new(AES_KEY, AES.MODE_OFB, IV)
    plain_OFB = cipher_OFB.decrypt(ciphertext_OFB_Mod)
    # plain_OFB = plain_OFB.decode()
    plain_OFB = urllib.parse.unquote(plain_OFB)
    print("OFB: ", plain_OFB)

    # Alter Bit then DECRYPT CTR
    ciphertext_CTR_Mod = modifyBit(ciphertext_CTR)
    countf = Counter.new(64, NONCE)
    cipher_CTR = AES.new(AES_KEY, AES.MODE_CTR, counter=countf)
    plain_CTR = cipher_CTR.decrypt(ciphertext_CTR_Mod)
    # plain_CTR = plain_CTR.decode()
    plain_CTR = urllib.parse.unquote(plain_CTR)
    print("CTR: ", plain_CTR)



   
   
    

   

    
    
   
   
   


main()
