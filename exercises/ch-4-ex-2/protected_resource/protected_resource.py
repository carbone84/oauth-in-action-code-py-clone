from flask import Flask
from flask import render_template, request
from tinydb import TinyDB, Query
from time import time

app = Flask(__name__)

db = TinyDB('../database.json')

protected_resource = {
    'name': 'Protected Resource',
    'description': 'This data has been protected by OAuth 2.0'
}

saved_words = []

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/words', methods=['GET','POST','DELETE'])
def words():
    access_token = ''
    access_token = getAccessToken()
    
    if access_token:
        print(request.method)
        if request.method == 'GET':
            
            #
            # Make this function require the "read" scope
            #
            return {'words': ' '.join(saved_words), 'timestamp': time()}
        elif request.method == 'POST':
            #
            # Make this function require the "write" scope
            #
            if request.form.get('word'):
                saved_words.append(request.form.get('word'))
                print(saved_words)
            return "added", 201
        elif request.method == 'DELETE':
            #
            # Make this function require the "delete" scope
            #
            saved_words.pop()
            return "popped", 204
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
        return token
    else:
        print("No matching token was found.")
        return