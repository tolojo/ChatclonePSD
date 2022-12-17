import hashlib
import secrets
import time
import tkinter
from socket import socket, AF_INET, SOCK_STREAM
from os import getcwd, path
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from Client import getUname

connected_to = ""
logged_in_user = ""


def putMessage(msg):
    msg_list.insert(tkinter.END, msg)


def sendMessage(msg, conn_user, logged_user):  # Handles sending of messages.

    # printing message to logged user's screen
    # msg_list.insert(tkinter.END, f"{logged_user.capitalize()}: {msg}")

    msg_list.insert(tkinter.END, msg)


    # encrypting message using connected user's symmetric key
    file = open('symmetricKeys/' + conn_user + '.key', 'rb')  # rb = read bytes
    key = file.read()
    file.close()
    fernet = Fernet(key)
    # log_message = fernet.encrypt(msg.encode())
    msg = fernet.encrypt(msg.encode())
    print(msg)

    # sending message to connected user
    client_socket.send(msg)

    # append message to file logged_user-conn_user.txt if exists, else create file and then append
    try:
        with open("chatLogs/"+conn_user+".txt", "ab") as f:
            f.write(msg)
        with open("chatLogs/" + conn_user + ".txt", "a") as f:
            f.write('\n')
    except:
        print("File doesn't exist")
        with open("chatLogs/"+conn_user+".txt", "wb") as f:
            print("File Created")
            f.write(msg)
        with open("chatLogs/" + conn_user + ".txt", "a") as f:
            f.write('\n')

    # msg = fernet.decrypt(msg)
    # msg_list.insert(tkinter.END, conn_user.encode('utf8') + b': ' + msg)
    # msg_list.insert(tkinter.END, f"{logged_user}: {msg.decode()}")

    # closing connection with connected user if message is 'quit'
    if msg == "{quit}":
        client_socket.close()
        top.quit()


def receive():

    # Handles receiving of messages.
    while True:
        try:
            msg = client_socket.recv(2048)
            file = open(f'symmetricKeys/{logged_in_user}.key', 'rb')  # rb = read bytes
            # file = open('symmetricKeys/' + getUname() + '.key', 'rb')  # rb = read bytes
            key = file.read()
            file.close()
            fernet = Fernet(key)
            msg = fernet.decrypt(msg)
            msg_list.insert(tkinter.END, f"receive function {msg}")
        except OSError:  # Possibly client has left the chat.
            break


def connect(port, conn_user, logged_user):
    # print(f"Connected to client: {conn_user}")
    global logged_in_user
    global connected_to
    global client_socket

    logged_in_user = logged_user
    connected_to = conn_user
    # connected_to = conn_user

    # print(f"Connected to user: {conn_user}")
    print(f"Connected to user: {conn_user}; on port: {port}\n")
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    client_socket.send(bytes(conn_user,'utf8'))
    time.sleep(1)

    try:
        print("uname::" + uname)
        f = open("symmetricKeys/"+uname+".key", "r")
    except:
        print("File doesn't exist")
        key = Fernet.generate_key()
        with open('asymmetricKeys/' + uname + '_client_public_key.pem', 'rb') as f:
            client_public_key = serialization.load_pem_public_key(
                f.read(),
                backend = default_backend()
            )
        encrypted_key = client_public_key.encrypt(
            key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None)
        )
        file = open('symmetricKeys/'+uname+'.key', 'wb')  # wb = write bytes
        file.write(key)
        print("key Generated")
        client_socket.send(encrypted_key)


def backup():
    # Generate a random secret key
    random_key = secrets.token_bytes(16)
    print('Key is: ', random_key, '\n')

    with open(f"chatLogs/{connected_to}.txt", "rb") as fi, open(f"chatLogs/{connected_to}_encrypted.txt", "wb") as fo:

        # Initialize the AES cipher with the derived key
        cipher = AES.new(random_key, AES.MODE_EAX)

        nonce = cipher.nonce

        # Read the file to encrypt, encrypt the data and write the encrypted data to a new file
        ciphertext, tag = cipher.encrypt(fi.read()), cipher.digest()
        fo.write(nonce + tag + ciphertext)

    shares = Shamir.split(2, 3, random_key, ssss=False)

    print('Original shares')
    print(shares)

    # Copy share 1 to the 'userShare' folder
    with open('userShare/share1.txt', 'wb') as f:
        for idx, share in shares:
            if idx == 1:
                f.write(share)

    # Copy share 2 to the 'Backup1' folder
    with open('../Backup1/share2.txt', 'wb') as f:
        for idx, share in shares:
            if idx == 2:
                f.write(share)

    # Copy share 2 to the 'Backup2' folder
    with open('../Backup2/share3.txt', 'wb') as f:
        for idx, share in shares:
            if idx == 3:
                f.write(share)


def restore():

    folders = ['userShare/share1.txt', '../Backup1/share2.txt', '../Backup2/share3.txt']

    with open(folders[0], 'rb') as f:
        share1 = f.read()
    with open(folders[1], 'rb') as f:
        share2 = f.read()
    with open(folders[2], 'rb') as f:
        share3 = f.read()

    shares = [share1, share2]

    indexed_shares = []

    for idx, share in enumerate(shares):
        index, share = idx, share
        indexed_shares.append((index + 1, share))

    print('\nReconstructed shares')
    print(indexed_shares)

    og_key = Shamir.combine(indexed_shares, ssss=False)

    print('\nReconstructed key is: ', og_key, '\n')

    with open(f"chatLogs/{connected_to}_encrypted.txt", "rb") as fi:

        # Initialize the AES cipher with the reconstructed key
        # Read the encrypted file, decrypt the data and write the decrypted data to a new file
        nonce, tag = [fi.read(16) for x in range(2)]
        cipher = AES.new(og_key, AES.MODE_EAX, nonce=nonce)
        try:
            result = cipher.decrypt(fi.read())
            cipher.verify(tag)
            with open(f"chatLogs/{connected_to}_cleartext.txt", "wb") as fo:
                fo.write(result)
        except ValueError:
            print("The shares were incorrect\n")

    with open("symmetricKeys/" + logged_in_user + ".key", "r") as f:
        fernet = Fernet(f.read())

    with open(f"chatLogs/{connected_to}_cleartext.txt", "r") as fi:
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
