import time
import tkinter
from socket import socket, AF_INET, SOCK_STREAM

from cryptography.fernet import Fernet

from Client import getUname


def putMessage(msg):
    msg_list.insert(tkinter.END, msg)

def sendMessage(msg,uname):  # event is passed by binders.
        # Handles sending of messages.

    file = open('symmetricKeys/' + uname + '.key', 'rb')  # rb = read bytes
    key = file.read()
    file.close()
    fernet = Fernet(key)
    msg = fernet.encrypt(msg.encode())
    print(msg)
    client_socket.send(msg)
    msg = fernet.decrypt(msg)
    msg_list.insert(tkinter.END, uname.encode('utf8') + b' : ' + msg)
    if msg == "{quit}":
       client_socket.close()
       top.quit()

def receive():
    #Handles receiving of messages.
    while True:
        try:
            msg = client_socket.recv(2048)
            file = open('symmetricKeys/' + getUname() + '.key', 'rb')  # rb = read bytes
            key = file.read()
            file.close()
            fernet = Fernet(key)
            msg = fernet.decrypt(msg)
            msg_list.insert(tkinter.END, msg)
        except OSError:  # Possibly client has left the chat.
            break


def connect(port, uname):
    global client_socket
    name = uname
    if(name == "tomas"):
        name = "joao"
    else :
        if(name == "joao"):
            name = "tomas"
    print("name::" + name)
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    client_socket.send(bytes(name,'utf8'))
    time.sleep(1)

    try:
        print("uname::"+ uname)
        f = open("symmetricKeys/"+uname+".key", "r")
    except:
        print("File doesn't exist")
        key = Fernet.generate_key()
        file = open('symmetricKeys/'+uname+'.key', 'wb')  # wb = write bytes
        file.write(key)
        print("key Generated")
        client_socket.send(key)

def chat_int(uname):
    global sUName
    sUName = uname
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
    top.title("Chat:= " + uname)

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

    connectButton = tkinter.Button(top, text="Send", command=(lambda: sendMessage(my_msg.get(), uname)))
    connectButton.pack()

    top.mainloop()
