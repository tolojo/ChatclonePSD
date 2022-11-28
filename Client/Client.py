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

serverUrl = 'http://127.0.0.1:3000/users/pkRegister'

clients = {}
addresses = {}
HOST = ''
PORT = 33000
BUFSIZ = 1024

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
    r = requests.post(serverUrl + "/" + username, files=files)


def logInRequest(uname, passwd):
    r = requests.post(url="http://127.0.0.1:3000/logIn", json=login(uname, passwd))
    if (r.status_code == 200):
        global username
        username = uname
        sendClientPK()
        connectedUserInt()




        ADDR = (HOST, PORT)

        SERVER = socket(AF_INET, SOCK_STREAM)
        SERVER.bind(ADDR)



def logIn_int():
    # window
    tkWindow = Tk()
    tkWindow.geometry('400x150')
    tkWindow.title('Login')
    # username label and text entry box
    usernameLabel = Label(tkWindow, text="User Name").grid(row=0, column=0)
    username = StringVar()
    usernameEntry = Entry(tkWindow, textvariable=username).grid(row=0, column=1)
    # password label and password entry box
    passwordLabel = Label(tkWindow, text="Password").grid(row=1, column=0)
    password = StringVar()
    passwordEntry = Entry(tkWindow, textvariable=password, show='*').grid(row=1, column=1)
    # login button
    loginButton = Button(tkWindow, text="Login", command=(lambda: logInRequest(username.get(), password.get()))).grid(
        row=4, column=0)
    registerButtom = Button(tkWindow, text="register", command=(lambda: regInt())).grid(
        row=4, column=1)
    tkWindow.mainloop()


if __name__ == "__main__":
    genClientKeys()
    logIn_int()

