from flask import Flask
from flask import render_template, request, g, make_response
from tinydb import TinyDB, Query
from functools import wraps
from time import time

app = Flask(__name__)

db = TinyDB('../database.json')

protected_resource = {
    'name': 'Protected Resource',
    'description': 'This data has been protected by OAuth 2.0'
}

def prerequisites(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            g.access_token = getAccessToken()
            if not g.access_token:
                return "Error", 401
            print(f"Found access token {g.access_token}")
            return f(*args, **kwargs)
        elif request.method == 'OPTIONS':
            return build_cors_preflight_response()
    return decorated_function

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/resource', methods=['POST', 'OPTIONS'])
@prerequisites
def resource():
    if g.access_token:
        response = make_response(protected_resource)
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response
    else:
        return "Error", 401

def getAccessToken():
    auth = request.headers.get('authorization')
    print(f"AUTH: {auth}")
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

def build_cors_preflight_response():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "*")
    # response.headers.add("Access-Control-Allow-Methods", "*")
    return response