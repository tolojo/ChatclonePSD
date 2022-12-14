import tkinter
from socket import socket, AF_INET, SOCK_STREAM


def putMessage(msg):
    msg_list.insert(tkinter.END, msg)

def sendMessage(msg,uname):  # event is passed by binders.
        # Handles sending of messages.
    msg = msg.encode('utf8')
    print(msg)
    client_socket.send(msg)
    msg_list.insert(tkinter.END, uname.encode('utf8') + b' : ' + msg)
    if msg == "{quit}":
       client_socket.close()
       top.quit()

def receive():
    #Handles receiving of messages.
    while True:
        try:
            msg = client_socket.recv(2048).decode("utf8")
            msg_list.insert(tkinter.END, msg)
        except OSError:  # Possibly client has left the chat.
            break

def connect(port):
    global client_socket
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))

def chat_int(uname):

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
