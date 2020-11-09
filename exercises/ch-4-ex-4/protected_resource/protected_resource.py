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

aliceFavorites = {
	'movies': ['The Multidmensional Vector', 'Space Fights', 'Jewelry Boss'],
	'foods': ['bacon', 'pizza', 'bacon pizza'],
	'music': ['techno', 'industrial', 'alternative']
};

bobFavorites = {
	'movies': ['An Unrequited Love', 'Several Shades of Turquoise', 'Think Of The Children'],
	'foods': ['bacon', 'kale', 'gravel'],
	'music': ['baroque', 'ukulele', 'baroque ukulele']
};


@app.before_request
def before_request():
    g.access_token = getAccessToken()
    if g.access_token:
        print(f"Found access token {g.access_token}")
    else:
        return "Error", 401

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/favorites')
def favorites():
    #
    # Get different user information based on the information of who approved the token
    #
    unknown = {'user': 'Unknown', 'favorites': {
        'movies': [], 'foods': [], 'music': []
    }}
    return unknown


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