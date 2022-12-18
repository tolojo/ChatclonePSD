import hashlib
import os
import secrets
import hmac
import time
import tkinter
from socket import socket, AF_INET, SOCK_STREAM
from os import getcwd, path
import json

import requests
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from Client import getUname

connected_to = ""
logged_in_user = ""
server_url_1 = '192.168.1.75:4000'
server_url_2 = '192.168.1.75:5000'

def putMessage(msg):
    msg_list.insert(tkinter.END, msg)


def sendMessage(msg, conn_user, logged_user):  # Handles sending of messages.

    # printing message to logged user's screen
    # msg_list.insert(tkinter.END, f"{logged_user.capitalize()}: {msg}")

    msg_list.insert(tkinter.END, logged_user.capitalize(), ": " + msg)

    # encrypting message using connected user's symmetric key
    file = open(f'symmetricKeys/{logged_user}_{conn_user}.key', 'rb')  # rb = read bytes
    key = file.read()
    file.close()
    fernet = Fernet(key)
    # log_message = fernet.encrypt(msg.encode())
    msg = fernet.encrypt(msg.encode())
    print(msg)

    # sending message to connected user
    client_socket.send(msg)

    hmac_sha = hmac.new(key,msg, digestmod='sha256')
    client_socket.send(hmac_sha.digest())

    # append message to file logged_user-conn_user.txt if exists, else create file and then append
    try:
        with open(f"chatLogs/{logged_user}_{conn_user}.txt", "ab") as f:
            f.write(msg)
        with open(f"chatLogs/{logged_user}_{conn_user}.txt", "a") as f:
            f.write('\n')
    except:
        print("File doesn't exist")
        with open(f"chatLogs/{logged_user}_{conn_user}.txt", "wb") as f:
            print("File Created")
            f.write(msg)
        with open(f"chatLogs/{logged_user}_{conn_user}.txt", "a") as f:
            f.write('\n')

    # closing connection with connected user if message is 'quit'
    if msg == "{quit}":
        client_socket.close()
        top.quit()


def connect(port, conn_user, logged_user):
    global logged_in_user
    global connected_to
    global client_socket

    logged_in_user = logged_user
    connected_to = conn_user

    print(f"Connected to user: {conn_user}; on port: {port}\n")
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    client_socket.send(bytes(logged_user,'utf8'))
    time.sleep(1)

    try:
        print("uname::" + conn_user)
        f = open(f"symmetricKeys/{logged_user}_{conn_user}.key", "r")
    except:
        print("File doesn't exist")
        key = Fernet.generate_key()
        with open('asymmetricKeys/' + conn_user + '_client_public_key.pem', 'rb') as f:
            client_public_key = serialization.load_pem_public_key(
                f.read(),
                backend = default_backend()
            )
        encrypted_key = client_public_key.encrypt(
            key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None)
        )
        file = open(f'symmetricKeys/{logged_user}_{conn_user}.key', 'wb')  # wb = write bytes
        file.write(key)
        print("key Generated")
        client_socket.send(encrypted_key)


def backup():

    # Set the endpoint URL
    url_backup1 = f"http://{server_url_1}/register_share_backup1"
    url_backup2 = f"http://{server_url_2}/register_share_backup2"
    url_backup_file_1 = f"http://{server_url_1}/register_file"
    url_backup_file_2 = f"http://{server_url_2}/register_file"

    # Generate a random secret key
    random_key = secrets.token_bytes(16)
    print('Key is: ', random_key, '\n')

    with open(f"chatLogs/{logged_in_user}_{connected_to}.txt", "rb") as fi, \
            open(f"chatLogs/{logged_in_user}_{connected_to}_encrypted.txt", "wb") as fo:

        # Initialize the AES cipher with the derived key
        cipher = AES.new(random_key, AES.MODE_EAX)

        nonce = cipher.nonce

        # Read the file to encrypt, encrypt the data and write the encrypted data to a new file
        ciphertext, tag = cipher.encrypt(fi.read()), cipher.digest()
        fo.write(nonce + tag + ciphertext)

    f = open(f"chatLogs/{logged_in_user}_{connected_to}_encrypted.txt", 'rb')
    text = f.read()
    # data = {'name': connected_to, 'file': text.decode('latin1')}
    register_file1 = requests.post(url_backup_file_1, json={'name': f"{logged_in_user}_{connected_to}",
                                                            'file': text.decode('latin1')})

    register_file2 = requests.post(url_backup_file_2, json={'name': f"{logged_in_user}_{connected_to}",
                                                            'file': text.decode('latin1')})

    f.close()

    shares = Shamir.split(2, 3, random_key, ssss=False)

    print('Original shares')
    print(shares)

    # Copy share 1 to the 'userShare' folder
    with open(f'userShare/{logged_in_user}_{connected_to}_share1.txt', 'wb') as f:
        for idx, share in shares:
            if idx == 1:
                f.write(share)

    # Set the data for the request body
    for idx, share in shares:
        if idx == 2:
            data = {'name': f"{logged_in_user}_{connected_to}",
                    'share': share.decode('latin1')}

            # Make the POST request
            response = requests.post(url_backup1, json=data)

        if idx == 3:
            data = {'name': f"{logged_in_user}_{connected_to}",
                    'share': share.decode('latin1')}

            # Make the POST request
            response = requests.post(url_backup2, json=data)


def restore():

    url_restore1 = f"http://{server_url_1}/get_share/{logged_in_user}_{connected_to}"
    url_restore2 = f"http://{server_url_2}/get_share/{logged_in_user}_{connected_to}"
    url_restore_file_1 = f"http://{server_url_1}/get_encrypted_file/{logged_in_user}_{connected_to}"
    url_restore_file_2 = f"http://{server_url_2}/get_encrypted_file/{logged_in_user}_{connected_to}"

    user_share_path = f'{os.getcwd()}/userShare/{logged_in_user}_{connected_to}_share1.txt'.replace('\\', '/')

    # Verify that 'userShare/{logged_in_user}_{connected_to}_share1.txt' exists
    server_1_status = False
    if os.path.exists(user_share_path):
        print("User share exists in local storage.")
        with open(user_share_path, 'rb') as f:
            share1 = f.read()

        try:
            # Make the GET request
            response1 = requests.get(url_restore1)
            share2 = response1.json()['share2'].encode('latin1')
            shares = [share1, share2]

        except:
            server_1_status = True
            print("Error: Server 1 is down")
            response2 = requests.get(url_restore2)
            share3 = response2.json()['share3'].encode('latin1')
            shares = [share1, share3]

    else:
        print("User share does not exist in local storage.")

        response1 = requests.get(url_restore1)
        share2 = response1.json()['share2'].encode('latin1')

        response2 = requests.get(url_restore2)
        share3 = response2.json()['share3'].encode('latin1')

        shares = [share2, share3]

    indexed_shares = []

    for idx, share in enumerate(shares):
        if os.path.exists(user_share_path):
            if idx == 0:
                indexed_shares.append((idx + 1, share))

            if idx == 1:
                if server_1_status:  # Server 1 is down
                    indexed_shares.append((idx + 2, share))
                else:
                    indexed_shares.append((idx + 1, share))

        else:
            indexed_shares.append((idx + 2, share))

    print('\nReconstructed shares')
    print(indexed_shares)

    og_key = Shamir.combine(indexed_shares, ssss=False)

    print('\nReconstructed key is: ', og_key, '\n')

    if os.path.exists(f"chatLogs/{logged_in_user}_{connected_to}_encrypted.txt"):
        enc_file = open(f"chatLogs/{logged_in_user}_{connected_to}_encrypted.txt", 'rb')

    else:
        response = requests.get(url_restore_file_1)
        enc_text = response.json()['encrypted_file'].encode('latin1')

        enc_file = open(f"chatLogs/{logged_in_user}_{connected_to}_encrypted.txt", "wb")
        enc_file.write(enc_text)
        enc_file.close()
        enc_file = open(f"chatLogs/{logged_in_user}_{connected_to}_encrypted.txt", 'rb')

    # Initialize the AES cipher with the reconstructed key
    # Read the encrypted file, decrypt the data and write the decrypted data to a new file
    nonce, tag = [enc_file.read(16) for x in range(2)]
    cipher = AES.new(og_key, AES.MODE_EAX, nonce=nonce)
    try:
        result = cipher.decrypt(enc_file.read())
        cipher.verify(tag)
        with open(f"chatLogs/{logged_in_user}_{connected_to}.txt", "wb") as fo:
            fo.write(result)
    except ValueError:
        print("The shares were incorrect\n")

    enc_file.close()

    with open(f"symmetricKeys/{logged_in_user}_{connected_to}.key", "r") as f:
        fernet = Fernet(f.read())

    with open(f"chatLogs/{logged_in_user}_{connected_to}.txt", "r") as fi:
        lines = fi.readlines()

        for index, line in enumerate(lines):
            if index % 2 != 0:
                # f.write(f"{logged_user.capitalize()}: {msg}\n")
                msg = fernet.decrypt(line)
                msg_list.insert(tkinter.END, f"{connected_to.capitalize()}: {msg.decode()}")
            else:
                msg = fernet.decrypt(line)
                msg_list.insert(tkinter.END, msg)


def chat_int(conn_user, logged_user):
    global sUName
    sUName = conn_user

    # call function when we click in the box
    def focusIn(entry, placeholder):
        if entry.get() == placeholder:
            entry.delete(0, tkinter.END)

    # call function when we click outside box
    def focusOut(entry, placeholder):
        if entry.get() == "":
            entry.insert(0, placeholder)

    global top
    top = tkinter.Tk()
    top.title(f"{logged_user.capitalize()}: Connected to {conn_user.capitalize()}")

    messages_frame = tkinter.Frame(top)

    scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
    global msg_list
    # Following will contain the messages.
    msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
    msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
    msg_list.pack()
    messages_frame.pack()

    my_msg = tkinter.StringVar()  # For the messages to be sent.
    placeholder = "Type your messages here."
    entry_field = tkinter.Entry(top, textvariable=my_msg)
    entry_field.bind("<FocusIn>", lambda e: focusIn(entry_field, placeholder))
    entry_field.bind("<FocusOut>", lambda e: focusOut(entry_field, placeholder))
    entry_field.pack()

    connectButton = tkinter.Button(top, text="Send", command=(lambda: sendMessage(my_msg.get(), conn_user, logged_user)))
    connectButton.pack()

    # create backup button
    backupButton = tkinter.Button(top, text="Create Backup", command=(lambda: backup()))
    backupButton.pack()

    backupButton = tkinter.Button(top, text="Retrieve Backup", command=(lambda: restore()))
    backupButton.pack()

    top.mainloop()
