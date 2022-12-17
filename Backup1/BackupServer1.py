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

UserPK_pair = {}

client = MongoClient("mongodb+srv://test:test@wpp-clone.ojoiv95.mongodb.net/?retryWrites=true&w=majority")
# db = client.get_database("userDatabase")
# users = db.User

# Connect to the MongoDB database
# client = MongoClient('mongodb://localhost:27017')
db = client['shares']

@app.route('/register_share', methods=['POST'])
def register_share():
    # Get the share data from the request body
    share = request.json['share']

    # Insert the share into the database
    result = db.shares.insert_one({'share': share})

    # Return the inserted share's ID
    return jsonify({'id': result.inserted_id}), 201

@app.route('/register_encrypted_file', methods=['POST'])
def register_encrypted_file():
    # Get the encrypted file data from the request body
    encrypted_file = request.json['encrypted_file']

    # Insert the encrypted file into the database
    result = db.encrypted_files.insert_one({'encrypted_file': encrypted_file})

    # Return the inserted file's ID
    return jsonify({'id': result.inserted_id}), 201

@app.route('/get_share/<share_id>', methods=['GET'])
def get_share(share_id):
    # Find the share with the given ID
    share = db.shares.find_one({'_id': share_id})

    # Return the share data
    return jsonify({'share': share['share']}), 200

@app.route('/get_encrypted_file/<file_id>', methods=['GET'])
def get_encrypted_file(file_id):
    # Find the encrypted file with the given ID
    encrypted_file = db.encrypted_files.find_one({'_id': file_id})

    # Return the encrypted file data
    return jsonify({'encrypted_file': encrypted_file['encrypted_file']}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000)


