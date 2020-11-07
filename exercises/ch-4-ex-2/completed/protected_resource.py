from flask import Flask
from flask import render_template, request, g
from tinydb import TinyDB, Query
from time import time

app = Flask(__name__)

db = TinyDB('../database.json')

protected_resource = {
    'name': 'Protected Resource',
    'description': 'This data has been protected by OAuth 2.0'
}

saved_words = []

@app.before_request
def before_request():
    g.access_token = getAccessToken()
    if g.access_token:
        print(f"Found access token {g.access_token}")
    else:
        print("No matching token was found.")
        return "Error", 401

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/words', methods=['GET','POST','DELETE'])
def words():
    if request.method == 'GET':
        if 'read' in g.access_token['scope']:
            return {'words': ' '.join(saved_words), 'timestamp': time()}
        else:
            return ("Insufficient scope", 403, {'WWW-Authenticate': 'Bearer realm=localhost:5002, error="insufficient_scope", scope="read"'})
    elif request.method == 'POST':
        if 'write' in g.access_token['scope']:
            if request.form.get('word'):
                saved_words.append(request.form.get('word'))
            return "added", 201
        else:
            return ("Insufficient scope", 403, {'WWW-Authenticate': 'Bearer realm=localhost:5002, error="insufficient_scope", scope="write"'})
    elif request.method == 'DELETE':
        if 'delete' in g.access_token['scope']:
            if len(saved_words) > 0:
                saved_words.pop()
            return "popped", 204
        else:
            return ("Insufficient scope", 403, {'WWW-Authenticate': 'Bearer realm=localhost:5002, error="insufficient_scope", scope="delete"'})
    else:
        return

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
        token = dict(tokens[0])
        print(f"We found a matching token: {token}")
        return token
    else:
        print("No matching token was found.")
        return