import json
import time
# import socket
import tkinter
from socket import *
from threading import Thread
import shutil
from tkinter import *
from os import getcwd, path
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from Users_int import *
from login import login
from register import regInt
import chat_Int
serverUrl = f"http://192.168.1.75:3000"


client_address = 0
cName = ""
username = ""
def getUname():
    return username


def setClient(conn_user):

    global cName
    cName = conn_user
    # print(f"Connected to user: {cName}")

def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected.\n" % client_address)
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    name = ""
    uname = client.recv(4096).decode('utf8')

    try:
        f = open(f'symmetricKeys/{username}_{uname}.key', 'r')
        f.close()

    except:
        print("Symmetric doesn't exist")
        msg = client.recv(8172)
        print(msg)
        print(name)
        path = getcwd()
        time.sleep(2)
        with open('asymmetricKeys/' + username + '_client_private_key.pem', 'rb') as f:
            client_private_key = serialization.load_pem_private_key(
                f.read(), 
                password=None,
            )
        key = client_private_key.decrypt(
            msg,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None)
        )
        print(key)
        time.sleep(1)
        file = open(f'symmetricKeys/{username}_{uname}.key', 'wb')  # wb = write bytes
        file.write(key)
        file.close()
        print("key file created")
    while True:
        msg = client.recv(BUFSIZ)
        f = open(f"symmetricKeys/{username}_{uname}.key", "rb")
        key = f.read()
        fernet = Fernet(key)
        print("key: " +key.decode())
        hmac_one = hmac.new(key, msg, digestmod='sha256').digest()
        messageHmac = client.recv(8192)
        print(hmac_one)
        print(messageHmac)
        if hmac.compare_digest(hmac_one, messageHmac):
            try:
                with open(f"chatLogs/{chat_Int.logged_in_user}_{chat_Int.connected_to}.txt", "ab") as f:
                    f.write(msg)
                with open(f"chatLogs/{chat_Int.logged_in_user}_{chat_Int.connected_to}.txt", "a") as f:
                    f.write('\n')
            except:
                print("File doesn't exist")
                with open(f"chatLogs/{chat_Int.logged_in_user}_{chat_Int.connected_to}.txt", "wb") as f:
                    print("File Created")
                    f.write(msg)
                with open(f"chatLogs/{chat_Int.logged_in_user}_{chat_Int.connected_to}.txt", "w") as f:
                    f.write('\n')

            msg = fernet.decrypt(msg)

        # conn_user = cName
        # print(type(conn_user))
        # print(conn_user)

            if msg != bytes("{quit}", "utf8"):

                # putMessage(uname+" : "+msg.decode('utf8'))
                putMessage(f"{(chat_Int.connected_to).capitalize()}: {msg.decode()}")

            else:
                client.send(bytes("{quit}", "utf8"))
                client.close()
                break


def serverSocket(Uport):
    HOST = ''
    PORT = Uport
    global BUFSIZ
    BUFSIZ = 1024
    global SERVER
    SERVER = socket()
    SERVER.bind((HOST, PORT))

    SERVER.listen(5)
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()

    print("Server socket a correr")

def genClientKeys(uname):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('asymmetricKeys/' + uname + '_client_private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('asymmetricKeys/' + uname + '_client_public_key.pem', 'wb') as f:
        f.write(pem)


def sendClientPK(uname):

    files = {'file': open('asymmetricKeys/' + uname + '_client_public_key.pem', 'rb')}
    r = requests.post(serverUrl + "/users/pkRegister/" + username, files=files)


def logInRequest(logged_user, passwd, port, tkWindow):
    r = requests.post(url=serverUrl+"/logIn", json=login(logged_user, passwd, port))
    if (r.status_code == 200):
        genClientKeys(logged_user)
        time.sleep(1)
        global Uport
        Uport = port
        tkWindow.destroy()
        global username
        username = logged_user
        sendClientPK(logged_user)
        serverSocket(port)
        connectedUserInt(logged_user)


def logIn_int():
    # window
    tkWindow = Tk()
    tkWindow.geometry()
    tkWindow.title('Welcome')
    
    # Username label and text entry box
    usernameLabel = Label(tkWindow, text="Username:")
    usernameLabel.grid(row = 0, column = 0, sticky = W, pady = 2)

    username = StringVar()
    usernameEntry = Entry(tkWindow, textvariable=username)  
    usernameEntry.grid(row = 0, column = 1, sticky = W, pady = 2, columnspan = 2)
    
    # Password label and password entry box
    passwordLabel = Label(tkWindow,text="Password:")
    passwordLabel.grid(row = 1, column = 0, sticky = W, pady = 2)

    password = StringVar()
    passwordEntry = Entry(tkWindow, textvariable=password, show='*')
    passwordEntry.grid(row = 1, column = 1, sticky = W, pady = 2, columnspan = 2)

    # Port label and password entry box
    portLabel = Label(tkWindow, text="Port:")
    portLabel.grid(row=2, column=0, sticky=W, pady=2)


    port = IntVar()
    portEntry = Entry(tkWindow, textvariable=port)
    portEntry.grid(row=2, column=1, sticky=W, pady=2, columnspan=2)

    
    # login button
    loginButton = Button(tkWindow, text="Login", command=(lambda: logInRequest(username.get(), password.get(),port.get(),tkWindow)))
    loginButton.grid(row = 3, column = 1, sticky = W, pady = 2, padx = 2)    
    
    registerButtom = Button(tkWindow, text="Register", command=(lambda: regInt()))
    registerButtom.grid(row=3, column=2, sticky=W, pady=2, padx=2)
    
    tkWindow.mainloop()


if __name__ == "__main__":
    logIn_int()
    

