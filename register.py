from tkinter import *
import requests

def data_to_json(uname, passwd):
    user_dict = {
        'uname': uname,
        'passwd': passwd
        }
    return user_dict

#window
tkWindow = Tk()  
tkWindow.geometry('400x150')  
tkWindow.title('Register')
#username label and text entry box
usernameLabel = Label(tkWindow, text="User Name").grid(row=0, column=0)
username = StringVar()
usernameEntry = Entry(tkWindow, textvariable=username).grid(row=0, column=1)  
#password label and password entry box
passwordLabel = Label(tkWindow,text="Password").grid(row=1, column=0)  
password = StringVar()
passwordEntry = Entry(tkWindow, textvariable=password, show='*').grid(row=1, column=1)  
#login button
loginButton = Button(tkWindow, text="Login", command=(lambda: requests.post(url = "http://127.0.0.1:3000/registerUser", json = data_to_json(username.get(), password.get())))).grid(row=4, column=0)  

tkWindow.mainloop()