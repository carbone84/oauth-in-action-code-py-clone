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
    access_token = ''
    getAccessToken()
    if access_token:
        return protected_resource
    else:
        return "Error", 401

def getAccessToken():
    auth = request.headers['authorization']
    in_token = ''
    if auth and auth.lower().index('bearer') == 0:
        in_token = auth[7:len(auth)]
    elif request.form.get('access_token'):
        in_token = request.form.get('access_token')
    elif request.args.get('access_token'):
        in_token = request.args.get('access_token')
    
    print(f"Incoming token: {in_token}")
    sql = Query()
    tokens = db.search(sql.access_token == in_token)
    if len(tokens) == 1:
        token = tokens[0]
        print(f"We found a matching token: {token}")
        access_token == token
    else:
        print("No matching token was found.")
    return