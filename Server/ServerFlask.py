from flask import Flask, request, jsonify, send_file
from pymongo import MongoClient
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from markupsafe import escape

app = Flask(__name__)

UserPK_pair = {}

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

@app.route('/logIn', methods=['POST'])  # Login do user
def userAuth():
    with open("server_private_key.pem", 'rb') as p:
        privateKey = serialization.load_pem_private_key(
            p.read(),
            password=None,
        )

    data = json.dumps(request.get_json())
    data = json.loads(data)

    login = users.find_one({"uname": data["uname"]})

    passwd = login["passwd"]
    aux = data["passwd"].encode("latin1")

    passwd = privateKey.decrypt(
        passwd,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aux = privateKey.decrypt(
        aux,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    passwd = passwd.decode('utf-8')
    aux = aux.decode('utf-8')


    if aux == passwd:
        UserPK_pair[data["uname"]] = {'ip': data["ip"]}
        return "User encontrado", 200

    else:
        return "User não encontrado", 404


@app.route('/registerUser', methods=['POST'])  # Login do user
def userReg():
    with open("server_private_key.pem", 'rb') as p:
        privateKey = serialization.load_pem_private_key(
            p.read(),
            password=None,
        )

    data = json.dumps(request.get_json())
    data = json.loads(data)
    aux = data["passwd"].encode("latin1")

    user_check = users.find_one({"uname": data["uname"]})


    if not user_check:
        register = users.insert_one({"uname": data["uname"], "passwd": aux})
        if register:
            return "User Registado", 200
        else:
            return "Houve um erro a criar o user", 404
    else:
        return "Username já existe", 401




@app.route('/users/pkRegister/<uname>', methods=['POST'])  # registar a PK do user no server
def pkRegister(uname):
    file = request.files['file']
    savename ="clientPK/"+uname + "_" + file.filename
    file.save(savename)
    aux = {
        UserPK_pair[uname].get('ip'),
        savename,
    }
    UserPK_pair[uname] = aux  # sub pk teste1 por futura PK

    return "Key adicionada ao dicionario"


@app.route('/retrieveServerPK', methods=['GET'])  # devolve a PK do server
def getServerPK():
    return send_file("server_public_key.pem", as_attachment=True)


@app.route('/users/pkRegister/<uname>', methods=['GET'])  # devolve a PK do user no server
def pkRetrieve(uname):
    return list(UserPK_pair[uname])

@app.route('/users', methods=['GET'])  # devolve a PK do user no server
def usersRetrieve():

    userList = list(UserPK_pair)
    userDict = {user: user for user in userList}
    return userDict



if __name__ == "__main__":
    try:
        f = open("server_private_key.pem", "r")

    except:
        print("File doesn't exist")
        genServerKeys()

    app.run(debug=True, host="127.0.0.1", port=3000)
