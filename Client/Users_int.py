from datetime import datetime
import json
from socket import *
from tkinter import *
import tkinter
from ast import *
import requests

from chat_Int import *
from Client import *

serverUrl = "http://192.168.1.237:3000"


def refreshUsers():
    r = requests.get(url=serverUrl+"/users")
    user = literal_eval(r.content.decode())

    # clear the text field before inserting new text
    msg_list.delete(0, tkinter.END)

    # insert current time in msg_list to know when refresh button was clicked
    string_before = f"Current Time: {datetime.now().strftime('%H:%M:%S')}"
    msg_list.insert(tkinter.END, string_before.center(len(string_before) + 12, "-"))
    msg_list.insert(tkinter.END, "\n")

    # print users online
    for aux in user:
        msg_list.insert(tkinter.END, aux)

    msg_list.insert(tkinter.END, '\n')
    string_after = "End of users list"
    msg_list.insert(tkinter.END, string_after.center(len(string_before) + 12, "_"))


def loadPort(conn_user, logged_user):
    file = requests.get(url=serverUrl+'/users/pkRegister/'+conn_user)

    with open("clientConnectionsKeys/"+conn_user+"_clientkey.pem",'wb') as f:
        f.write(file.content)

    r = requests.get(url=serverUrl+"/users/ip/"+conn_user)
    port = json.loads(r.content.decode())
    # print(port["port"])
    connect(port["port"], conn_user, logged_user)
    setClient(conn_user)
    top.destroy()
    chat_int(conn_user, logged_user)


def connectedUserInt(logged_user):
    print(f'Logged in as: {logged_user}\n')

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
    top.title(f"Select User (Logged in as: {logged_user})")

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

    placeholder = "Select User"
    user = StringVar()
    entry_field = tkinter.Entry(top, textvariable=user)
    entry_field.bind("<FocusIn>", lambda e: focusIn(entry_field, placeholder))
    entry_field.bind("<FocusOut>", lambda e: focusOut(entry_field, placeholder))
    entry_field.pack()
    refreshUserButton = tkinter.Button(top, text="refresh", command=(lambda: refreshUsers()))
    refreshUserButton.pack()

    connectButton = tkinter.Button(top, text="connect", command=(lambda: loadPort(user.get(), logged_user)))
    connectButton.pack()

    top.mainloop()

