from tkinter import *
import requests

def data_to_dict(uname, passwd):
    user_dict = {
        'uname': uname,
        'passwd': passwd
        }
    return user_dict

def request_response(username, password):
    data = data_to_dict(username.get(), password.get())
    post = requests.post('http://127.0.0.1:3000/registerUser', json = data)
    return post.text
     
def close():
    tkWindow.destroy()
    
def combine_funcs(*funcs):
    def combined_func(*args, **kwargs):
        for f in funcs:
            f(*args, **kwargs)
    return combined_func

# Root window
tkWindow = Tk()  
tkWindow.title('Register')

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

response = Label(tkWindow,text="")
response.grid(row = 5, column = 1, sticky = W, pady = 2)

# Register button
registerButton = Button(tkWindow, text="Register", command = combine_funcs((lambda: response.config(text=request_response(username, password))), (lambda: requests.post(url = "http://127.0.0.1:3000/registerUser", json = data_to_dict(username.get(), password.get())))))

button_exit = Button(tkWindow, text = "Exit", command = close)

registerButton.grid(row = 3, column = 1, sticky = W, pady = 2)
button_exit.grid(row = 3, column = 2, sticky = W, pady = 2)  

tkWindow.mainloop()