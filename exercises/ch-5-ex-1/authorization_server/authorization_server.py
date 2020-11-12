from flask import Flask
from flask import render_template, redirect, request
import secrets, base64
from tinydb import TinyDB, Query

app = Flask(__name__)

db = TinyDB('../database.json')

codes = {}
requests = {}

# authorization server information
auth_server = {
    'authorization_endpoint': 'http://localhost:5001/authorize',
    'token_endpoint': 'http://localhost:5001/token'
}

# client information
clients = [
    #
    # Enter client information here
    #
]

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', clients=clients, auth_server=auth_server)

@app.route('/authorize', methods=['GET'])
def authorize():
    #
    # Process the request, validate the client, and send the user to the approval page
    #
    return render_template('index.html', clients=clients, auth_server=auth_server)

@app.route('/approve', methods=['GET', 'POST'])
def approve():
    #
    # Process the results of the approval page, authorize the client
    #
    return render_template('index.html', clients=clients, auth_server=auth_server)

@app.route('/token', methods=['POST'])
def token():
    #
    # Process the request, issue an access token
    #
    return render_template('index.html', clients=clients, auth_server=auth_server)

def getClient(client_id):
    for client in clients:
        if client['client_id'] == client_id:
            return client
    return "Client not found"

db.truncate()
