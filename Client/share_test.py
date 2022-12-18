import hashlib
import time
import tkinter
from socket import socket, AF_INET, SOCK_STREAM
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes
import os
from binascii import unhexlify
from binascii import hexlify
import secrets


# def backup():
#     random_key = secrets.token_bytes(16)
#     print('Key is: ', random_key, '\n')
#
#     with open("chatLogs/joao.txt", "rb") as fi, open("chatLogs/joao_encrypted.txt", "wb") as fo:
#
#         # Initialize the AES cipher with the derived key
#         cipher = AES.new(random_key, AES.MODE_EAX)
#
#         nonce = cipher.nonce
#
#         # Read the file to encrypt, encrypt the data and write the encrypted data to a new file
#         ciphertext, tag = cipher.encrypt(fi.read()), cipher.digest()
#         fo.write(nonce + tag + ciphertext)
#
#     shares = Shamir.split(2, 3, random_key, ssss=False)
#
#     print('Original shares')
#     print(shares)
#
#     # Copy share 1 to the 'Backup1' folder
#     with open('../Backup1/share1.txt', 'wb') as f:
#         for idx, share in shares:
#             if idx == 1:
#                 f.write(share)
#
#     # Copy share 2 to the 'Backup2' folder
#     with open('../Backup2/share2.txt', 'wb') as f:
#         for idx, share in shares:
#             if idx == 2:
#                 f.write(share)
#
#     # Copy share 3 to the 'share' folder
#     with open('share/share3.txt', 'wb') as f:
#         for idx, share in shares:
#             if idx == 3:
#                 f.write(share)
#
#
# def restore():
#
#     folders = ['../Backup1/share1.txt', '../Backup2/share2.txt', 'share/share3.txt']
#
#     with open(folders[0], 'rb') as f:
#         share1 = f.read()
#     with open(folders[1], 'rb') as f:
#         share2 = f.read()
#     with open(folders[2], 'rb') as f:
#         share3 = f.read()
#
#     shares = [share1, share2, share3]
#     indexed_shares = []
#
#     for idx, share in enumerate(shares):
#         index, share = idx, share
#         indexed_shares.append((index+1, share))
#
#     print('\nReconstructed shares')
#     print(indexed_shares)
#
#     og_key = Shamir.combine(indexed_shares, ssss=False)
#
#     print('\nReconstructed key is: ', og_key, '\n')
#
#     with open("chatLogs/joao_encrypted.txt", "rb") as fi:
#
#         # Initialize the AES cipher with the reconstructed key
#         # Read the encrypted file, decrypt the data and write the decrypted data to a new file
#         nonce, tag = [fi.read(16) for x in range(2)]
#         cipher = AES.new(og_key, AES.MODE_EAX, nonce=nonce)
#         try:
#             result = cipher.decrypt(fi.read())
#             cipher.verify(tag)
#             with open("cleartext.txt", "wb") as fo:
#                 fo.write(result)
#         except ValueError:
#             print("The shares were incorrect")
#
#     with open ("symmetricKeys/" + uname + ".key", "r") as f:
#         fernet = Fernet(f.read())
#
#     with open
#         msg = fernet.decrypt(msg)

# backup()
# restore()

def decrypt():

    with open("symmetricKeys/joao.key", "r") as f:
        fernet = Fernet(f.read())

    with open("chatLogs/tomas_cleartext.txt", "r") as fi:
        lines = fi.readlines()

        for line in lines:
            # f.write(f"{logged_user.capitalize()}: {msg}\n")
            print(line)

            encrypted_msg = line.split(": ")[1]
            print(encrypted_msg)

            msg = fernet.decrypt(encrypted_msg)
            print(msg)
            # msg_list.insert(tkinter.END, f"{logged_in_user.capitalize()}: {msg}")


decrypt()