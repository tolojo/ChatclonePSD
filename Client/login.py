from socket import *
from tkinter import *
from functools import partial
import requests
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def login(uname, passwd):
    hostname = gethostname()
    host_ip = gethostbyname_ex(hostname)[2][1]
    response = requests.get(url=f"http://{host_ip}:3000/retrieveServerPK")
    hostname = gethostname()
    with open('server_public_key.pem', 'wb') as f:
        f.write(response.content)
    f = open('server_public_key.pem', "r")
    while f.read() == "":
        f = open('server_public_key.pem', "r")

    with open("server_public_key.pem", 'rb') as p:
        publicKey = serialization.load_pem_public_key(
            p.read()
        )

    passwd = publicKey.encrypt(passwd.encode(), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    passwd = passwd.decode('latin1')

    user_dict = {
        'uname': uname,
        'passwd': passwd,
        'ip': host_ip,
        }
    return user_dict


