#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
import json
import tkinter
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import shutil
import socket

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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

    with open('Client/client_private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('Client/client_public_key.pem', 'wb') as f:
        f.write(pem)

def sendClientPK():

    hostname = socket.gethostname()
    user_dict = {
        'uname': 'tomas',
        'ip': socket.gethostbyname(hostname),
    }

    files = {'file': open('Client/client_public_key.pem', 'rb')}

    r = requests.post('http://127.0.0.1:3000/users/pkRegister',data={'file': files},json=user_dict),
    print(r.status_code)

""""
def receive():
    #Handles receiving of messages.
    while True:
        try:
            msg = client_socket.recv(BUFSIZ).decode("utf8")
            msg_list.insert(tkinter.END, msg)
        except OSError:  # Possibly client has left the chat.
            break


def send(event=None):  # event is passed by binders.
    #Handles sending of messages.
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    client_socket.send(bytes(msg, "utf8"))
    if msg == "{quit}":
        client_socket.close()
        top.quit()
"

def on_closing(event=None):
    #This function is to be called when the window is closed.
    my_msg.set("{quit}")
    send()
"""""""
top = tkinter.Tk()
top.title("Chat App")

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.

# call function when we click in the box
def focusIn(entry, placeholder):
    if entry.get() == placeholder:
        entry.delete(0, tkinter.END)
        
# call function when we click outside box
def focusOut(entry, placeholder):
    if entry.get() == "":
        entry.insert(0, placeholder)

my_msg.set("Type your messages here.")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

placeholder = "Type your messages here."
entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<FocusIn>", lambda e: focusIn(entry_field, placeholder))
entry_field.bind("<FocusOut>", lambda e: focusOut(entry_field, placeholder))
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

#----Now comes the sockets part----
HOST = input('Enter host: ')
PORT = input('Enter port: ')
if not PORT:
    PORT = 33000
else:
    PORT = int(PORT)

BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.
"""
genClientKeys()
sendClientPK()