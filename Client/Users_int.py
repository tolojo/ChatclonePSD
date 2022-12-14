import json
from socket import *
from tkinter import *
import tkinter
from ast import *
import requests

from chat_Int import *
from Client import *

hostname = gethostname()
host_ip = gethostbyname_ex(hostname)[2][1]
serverUrl = f"http://{host_ip}:3000"



def refreshUsers():
    r = requests.get(url=serverUrl+"/users")
    user = literal_eval(r.content.decode())
    print(type(user))
    for aux in user:
        print(aux)
        msg_list.insert(tkinter.END, aux)
    msg_list.insert(tkinter.END,"-----------------------")


def loadPort(uname):
    file = requests.get(url=serverUrl+'/users/pkRegister/'+uname)

    with open("clientConnectionskeys/"+uname+"_clientkey") as f:
        f.write(file.content)

    r = requests.get(url=serverUrl+"/users/ip/"+uname)
    port = json.loads(r.content.decode())
    print(port["port"])
    connect(port["port"])
    setClient(uname)
    top.destroy()
    chat_int(uname)


def connectedUserInt():

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
    top.title("Select User")

    messages_frame = tkinter.Frame(top)
    my_msg = tkinter.StringVar()  # For the messages to be sent.

    my_msg.set("Type your messages here.")
    scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
    global msg_list
    # Following will contain the messages.
    msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
    msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
    msg_list.pack()
    messages_frame.pack()

    placeholder = "Type your messages here."
    user = StringVar()
    entry_field = tkinter.Entry(top, textvariable=user)
    entry_field.bind("<FocusIn>", lambda e: focusIn(entry_field, placeholder))
    entry_field.bind("<FocusOut>", lambda e: focusOut(entry_field, placeholder))
    entry_field.pack()
    refreshUserButton = tkinter.Button(top, text="refresh", command=(lambda: refreshUsers()))
    refreshUserButton.pack()

    connectButton = tkinter.Button(top, text="connect", command=(lambda: loadPort(user.get())))
    connectButton.pack()

    top.mainloop()
