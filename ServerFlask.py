from flask import Flask, request
from pymongo import MongoClient
import json

app = Flask(__name__)
UserPK_pair = {
}
client = MongoClient("mongodb+srv://test:test@wpp-clone.ojoiv95.mongodb.net/?retryWrites=true&w=majority")
db = client.get_database("userDatabase")
users = db.User


@app.route('/users', methods=['POST'])
def list_programming_languages():
    data = json.dumps(request.get_json())
    data = json.loads(data)
    print(data)
    login = users.find_one({"uname": data["uname"], "passwd": data["passwd"]})
    if (login):
        return "User encontrado"
    else:
        return "User não encontrado"

@app.route('/users/pkRegister', methods=['POST']) #registar a PK do user no server
def list_programming_languages():
    data = json.dumps(request.get_json())
    data = json.loads(data)
    print(data)
    login = users.find_one({"uname": data["uname"], "passwd": data["passwd"]})
    if (login):
        return "User encontrado"
    else:
        return "User não encontrado"



if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=3000)
