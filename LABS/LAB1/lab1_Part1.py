from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad

hex_val = 'ff'  # 1111 1111

AES_KEY_SIZE = 16
AES_KEY = bytes.fromhex(hex_val) * AES_KEY_SIZE

RC4_KEY_SIZE = 5
RC4_KEY = bytes.fromhex(hex_val) * RC4_KEY_SIZE


def main():
    encrypt_AES()
    RC4_ciphertext = encrypt_RC4()
    decrypt_RC4(RC4_ciphertext)


def encrypt_AES():

    plaintext = "this is the wireless security lab"
    cipher = AES.new(AES_KEY, AES.MODE_ECB)

    plaintext = plaintext.encode()
    ciphertext = b''

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    print("AES: ", ciphertext)

    return ciphertext


def encrypt_RC4():

    plaintext = "this is the wireless security lab"
    cipher = ARC4.new(RC4_KEY)

    plaintext = plaintext.encode()

    ciphertext = b''

    ciphertext = cipher.encrypt(plaintext)

    print("RC4: ", ciphertext)

    return ciphertext


# def decrypt_AES(ciphertext):
    # It is possible we could get lucky and happen to stumble upon the right decryption
    # But it is most likely it would take us to the end of time to crack this!


def decrypt_RC4(ciphertext):

    S = list(range(256))
    j = 0
    output = []
    test_Key = bytes.fromhex('FF') * RC4_KEY_SIZE
    plain_Key = int.from_bytes(test_Key, 'big')

    while plain_Key > 0:

        test_Key = plain_Key.to_bytes(RC4_KEY_SIZE, 'big')
        listObj = list(S)

        for i in listObj:
            j = (j + S[i] + test_Key[i % RC4_KEY_SIZE]) % 256
            S[i], S[j] = S[j], S[i]

        i = j = 0
        for char in ciphertext:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            output.append(chr(char ^ S[(S[i] + S[j]) % 256]))

        decrypted = ''.join(output)
        if (decrypted == "this is the wireless security lab"):
            print(decrypted)
            break
        plain_Key = int.from_bytes(test_Key, 'big')
        plain_Key = plain_Key - 1


main()
