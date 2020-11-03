from flask import Flask
from flask import render_template, request
from tinydb import TinyDB, Query

app = Flask(__name__)

db = TinyDB('../database.json')

protected_resource = {
    'name': 'Protected Resource',
    'description': 'This data has been protected by OAuth 2.0'
}

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/resource', methods=['POST'])
def resource():
    #
    # Check to see if the access token was found or not
    #
    return

def getAccessToken():
    # 
    # Scan for an access token on the incoming request
    # 
    return