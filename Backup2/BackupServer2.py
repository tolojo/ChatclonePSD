from os import getcwd, path

from flask import Flask, request, jsonify, send_file
from pymongo import MongoClient
import json
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from markupsafe import escape

app = Flask(__name__)

client = MongoClient("mongodb+srv://test:test@wpp-clone.ojoiv95.mongodb.net/?retryWrites=true&w=majority")
# db = client.get_database("userDatabase")
db = client.get_database('shares')

shares = db.Backup2


@app.route('/register_share_backup2', methods=['POST'])
def register_share():

    # Get the share data from the request body
    data = json.dumps(request.get_json())
    data = json.loads(data)

    del_previous_entry = shares.delete_one({'name': data['name']})

    name = data["name"]
    share = data["share"].encode("latin1")

    # Insert the share into the database
    register_share = shares.insert_one({"name": name, 'share3': share})

    # Return the inserted share's ID
    return 'Share 3 criada', 201


@app.route(f'/get_share/<uname>', methods=['GET'])
def get_share(uname):
    # print(uname)
    # Find the share with the given ID
    data = shares.find_one({'name': uname})

    # Return the share data
    return {'share3': data['share3'].decode('latin1')}, 200


@app.route('/register_file', methods=['POST'])
def register_encrypted_file():

    # Get the encrypted file data from the request body
    data = json.dumps(request.get_json())
    data = json.loads(data)

    # Delete previous entry
    del_previous_entry = shares.delete_one({'file_name': data['name']})

    # Insert new entry
    name = data["name"]
    encrypted_file = data["file"].encode("latin1")

    # Insert the encrypted file into the database
    register_file = shares.insert_one({'file_name': name,
                                       'encrypted_file': encrypted_file})

    # Return the inserted file's ID
    return 'Encrypted log added to database', 201


@app.route('/get_encrypted_file/<uname>', methods=['GET'])
def get_encrypted_file(uname):
    # Find the encrypted file with the given ID
    get_file = shares.find_one({'file_name': uname})

    # Return the encrypted file data
    return {'encrypted_file': get_file['encrypted_file'].decode('latin1')}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


