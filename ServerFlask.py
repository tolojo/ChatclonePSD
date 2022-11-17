from flask import Flask, request
from pymongo import MongoClient
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
UserPK_pair = {
}
client = MongoClient("mongodb+srv://test:test@wpp-clone.ojoiv95.mongodb.net/?retryWrites=true&w=majority")
db = client.get_database("userDatabase")
users = db.User
def genServerKeys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('server_private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('server_public_key.pem', 'wb') as f:
        f.write(pem)


@app.route('/logIn', methods=['POST']) #Login do user
def userAuth():
    data = json.dumps(request.get_json())
    data = json.loads(data)
    print(data)
    login = users.find_one({"uname": data["uname"], "passwd": data["passwd"]})
    if login:
        return "User encontrado"
    else:
        return "User não encontrado"

@app.route('/registerUser', methods=['POST']) #Login do user
def userReg():
    data = json.dumps(request.get_json())
    data = json.loads(data)
    print(data)
    login = users.find_one({"uname": data["uname"], "passwd": data["passwd"]})
    if login:
        return "User encontrado"
    else:
        return "User não encontrado"

@app.route('/users/pkRegister', methods=['POST']) #registar a PK do user no server
def pkRegister():
    data = json.dumps(request.get_json())
    data = json.loads(data)
    print(data)
    UserPK_pair[data["uname"]] = "PK teste1" # sub pk teste1 por futura PK
    print(UserPK_pair)
    return list(UserPK_pair.items())


@app.route('/users/retrieveServerPK', methods=['GET']) #registar a PK do user no server
def getServerPK():
    pk = open("server_private_key.pem", "r")
    print(pk.read())
    return pk.read()



@app.route('/users/pkRegister/<uname>', methods=['GET']) #registar a PK do user no server
def pkRetrieve(uname):
    return UserPK_pair[uname]



if __name__ == "__main__":
    try:
        f = open("server_private_key.pem", "r")
        print(f.read())
    except:
        print("File doesn't exist")
        genServerKeys()



    app.run(debug=True, host="127.0.0.1", port=3000)
