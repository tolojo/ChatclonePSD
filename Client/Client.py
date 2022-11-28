import json
import tkinter
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import shutil
import socket
from tkinter import *

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from Users_int import *
from login import login
from register import regInt

serverUrl = 'http://127.0.0.1:3000'


def serverSocket():
    SERVER.listen(5)
    print("Server socket a correr")

def genClientKeys():
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

    with open('client_private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('client_public_key.pem', 'wb') as f:
        f.write(pem)


def sendClientPK():
    files = {'file': open('client_public_key.pem', 'rb')}
    r = requests.post(serverUrl + "/users/pkRegister/" + username, files=files)


def logInRequest(uname, passwd,tkWindow):
    r = requests.post(url=serverUrl+"/logIn", json=login(uname, passwd))
    if (r.status_code == 200):
        tkWindow.destroy()
        global username
        username = uname
        sendClientPK()
        serverSocketThread = Thread(target=serverSocket())
        serverSocketThread.start()
        connectedUserInt()





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
    
    # login button
    loginButton = Button(tkWindow, text="Login", command=(lambda: logInRequest(username.get(), password.get(),tkWindow)))
    loginButton.grid(row = 3, column = 1, sticky = W, pady = 2, padx = 2)    
    
    registerButtom = Button(tkWindow, text="Register", command=(lambda: regInt()))
    registerButtom.grid(row = 3, column = 2, sticky = W, pady = 2, padx = 2)
    
    tkWindow.mainloop()




clients = {}
addresses = {}

HOST = socket.gethostname()
PORT = 33000
BUFSIZ = 1024


SERVER = socket.socket()
SERVER.bind((HOST,PORT))
if __name__ == "__main__":

    genClientKeys()
    logIn_int()

