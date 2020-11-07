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
    {
        'client_id': 'oauth-client-1',
        'client_secret': 'oauth-client-secret-1',
        'redirect_uris': ['http://localhost:5000/callback'],
        'scope': 'read write delete'
    }
]

user_info = {
    'alice': {
		'sub': '9XE3-JI34-00132A',
		'preferred_username': 'alice',
		'name': 'Alice',
		'email': 'alice.wonderland@example.com',
		'email_verified': True
	},
	
	'bob': {
		'sub': '1ZT5-OE63-57383B',
		'preferred_username': 'bob',
		'name': 'Bob',
		'email': 'bob.loblob@example.net',
		'email_verified': False
	},

	'carol': {
		'sub': 'F5Q1-L6LGG-959FS',
		'preferred_username': 'carol',
		'name': 'Carol',
		'email': 'carol.lewis@example.net',
		'email_verified': True,
		'username' : 'clewis',
		'password' : 'user password!'
 	}	
}

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', clients=clients, auth_server=auth_server)

@app.route('/authorize', methods=['GET'])
def authorize():
    client = getClient(request.args.get('client_id', ''))
    
    if not client:
        print(f"Unknown client {request.args.get('client_id', '')}")
        return render_template('error.html', error="Unknown client")
    elif request.args.get('redirect_uri', '') not in client['redirect_uris']:
        print(f"Mismatched redirect URI, expected {client.redirect_uris} got {request.args.get('redirect_uri', '')}")
        return render_template('error', error="Invalid redirect URI")
    else:
        rscope = set(request.args.get('scope', '').split(' ')) if request.args.get('scope', '') else set()
        cscope = set(client['scope'].split(' ')) if client['scope'] else set()
        if len(rscope.difference(cscope)) > 0:
            # look into url.parse in js>py
            redirect_url = request.args.get('redirect_uri') + "?error=invalid_scope"
            return redirect(redirect_url)
        
        request_id = secrets.token_urlsafe(8)
        requests[request_id] = request.args
        return render_template('approve.html', client=client, request_id=request_id, scope=rscope)

@app.route('/approve', methods=['GET', 'POST'])
def approve():
    request_id = request.form.get('request_id')
    query = requests[request_id]
    del requests[request_id]
    if not query:
        return render_template('error.html', error="No matching authorization request")
    
    if request.form.get('approve'):
        if query['response_type'] == 'code':
            code = secrets.token_urlsafe(8)
            user = request.form.get('user') #req.body.user?
            
            scope = set({r.replace("scope_", "") for r in dict(filter(lambda s: 'scope_' in s[0], request.form.items())).keys()})
            client = getClient(query['client_id'])
            cscope = set(client['scope'].split(' ')) if client['scope'] else set()
            if len(scope.difference(cscope)) > 0:
                redirect_url = query['redirect_uri'] + "?error=invalid_scope"
                return redirect(redirect_url)
            
            codes[code] = {
                'authorization_endpoint_request': query,
                'scope': scope,
                'user': user
            }
            
            # look into url.parse in js>py
            callback_url = query['redirect_uri'] + f"?code={code}&state={query['state']}"
            return redirect(callback_url)
        elif query['response_type'] == 'token':
            user = request.form.get('user')
            scope = set({r.replace("scope_", "") for r in dict(filter(lambda s: 'scope_' in s[0], request.form.items())).keys()})
            client = getClient(query['client_id'])
            cscope = set(client['scope'].split(' ')) if client['scope'] else set()
            if len(scope.difference(cscope)) > 0:
                print(f"scope: {scope}")
                print(f"cscope: {cscope}")

                redirect_url = query['redirect_uri'] + "?error=invalid_scope"
                return redirect(redirect_url)
            user = user_info[user]
            if not user:
                print(f"Unknown user: {user}")
                return render_template('error.html', error=f"Unknown user: {user}")
            print(f"User: {user}")
            
            token_response = generateTokens(query['client_id'], user, rscope)
            redirect_url = query['redirect_uri']
            if query['state']:
                token_response['state'] = query['state']
            #redirect_url.hash = qs.stringify(token_response)
            return redirect(redirect_url)
        else:
            error = "unsupported_response_type"
            callback_url = query['redirect_uri'] + f"?error={error}"
            return redirect(callback_url)
    else:
        error = "access_denied"
        callback_url = query['redirect_uri'] + f"?error={error}"
        return redirect(callback_url)

@app.route('/token', methods=['POST'])
def token():
    auth = request.headers['authorization']
    if auth:
        client_credentials_b64 = auth[8:len(auth)-1].encode()
        client_credentials_bytes = base64.b64decode(client_credentials_b64)
        client_credentials = client_credentials_bytes.decode('ascii').split(':')
        client_id = client_credentials[0]
        client_secret = client_credentials[1]

    if request.args.get('client_id', ''):
        if client_id:
            print("Client attempted to authenticate with multiple methods")
            return "invalid_client", 401
        
        client_id = request.args.get['client_id']
        client_secret = request.args.get['client_secret']

    client = getClient(client_id)
    
    if not client:
        print(f"Unknown client {client_id}")
        return "invalid_client", 401
    if client['client_secret'] != client_secret:
        print(f"Mismatched client secret, expected {client.client_secret} got {client_secret}")
        return "invalid_client", 401
    if request.form.get('grant_type') == 'authorization_code':
        code = codes[request.form.get('code')]
        if code:
            del codes[request.form.get('code')]
            if code['authorization_endpoint_request']['client_id'] == client_id:
                #user = user_info[code['user']]
                if code['scope']:
                    scope = code['scope']
                else:
                    scope = ''
                #token_response = generateTokens(client_id, user, code['scope'], code['authorization_endpoint_request']['nonce'], True)
                token_response = generateTokens(client_id, '', scope, '', True)

                print(f"Issued tokens for code {request.form.get('code')}")
                return token_response, 200
            else:
                print(f"Client mismatch, expected {code['authorization_endpoint_request']['client_id']} got {client_id}")
                return "invalid_grant", 400
        else:
            print(f"Unknown code, {request.args.get('code')}")
            return "invalid_grant", 400
    elif request.form.get('grant_type') == 'client_credentials':
        scope = set({r.replace("scope_", "") for r in dict(filter(lambda s: 'scope_' in s[0], request.form.items())).keys()})
        client = getClient(query['client_id'])
        cscope = set(client['scope'].split(' ')) if client['scope'] else set()
        if len(scope.difference(cscope)) > 0:
            print(f"scope: {scope}")
            print(f"cscope: {cscope}")
            redirect_url = query['redirect_uri'] + "?error=invalid_scope"
            return redirect(redirect_url)
        access_token = secrets.token_urlsafe(32)
        token_response = {
            'access_token': access_token,
            'token_type': 'Bearer',
            'scope': scope
        }
        db.insert({
            'access_token': access_token,
            'client_id': 'client_id',
            'scope': scope
        })
        print(f"Issuing access token {access_token}")
        return token_reponse, 200
    elif request.form.get('grant_type') == 'refresh_token':
        #call db to check for refresh token
        sql = Query()
        tokens = db.search(sql.refresh_token == request.form.get('refresh_token'))
        if len(tokens) == 1:
            token = tokens[0]
            if token['client_id'] != client_id:
                print(f"Invalid client using a refresh token, expected {token['client_id']} got {client_id}")
                db.remove(sql.refresh_token == request.form.get('refresh_token'))
                return 400
            print(f"We found a matching refresh token: {request.form.get('refresh_token')}")
            access_token = secrets.token_urlsafe(32)
            token_response = {
                    'access_token': access_token,
                    'token_type': 'Bearer',
                    'refresh_token': request.form.get('refresh_token')
                }
            db.insert({
                    'access_token': access_token,
                    'client_id': token['client_id']
                })
            print(f"Issuing access token {access_token} for refresh token {request.form.get('refresh_token')}")
            return token_response, 200
        else:
            print("No matching token was found.")
            return 401
    elif request.form.get('grant_type') == 'password':
        username = request.form.get('username')
        user = getUser(username)
        if not user:
            print(f"Unknown user {user}")
            return 'invalid_grant', 401
        print(f"User is {user}")

        password = request.form.get('password')
        if user['password'] != password:
            print(f"Mismatched resource owner password, expected {user['password']} got {password}")
            return 'invalid_grant', 401
        scope = request.form.get('scope')
        token_response = generateTokens(client_id, user, scope)
        print(f"token_response: {token_response}")
        return token_response, 200
    else:
        print(f"Unknown grant type, {request.args.get('grant_type')}")
        return "unsupported_grant_type", 400

def getClient(client_id):
    for client in clients:
        if client['client_id'] == client_id:
            return client
    return "Client not found"

def getUser(username):
    for user in user_info:
        if user['username'] == username:
            return user
    return "User not found"

def generateTokens(client_id, user, scope, nonce, generateRefreshToken):
    access_token = secrets.token_urlsafe(32)
    refresh_token = ''

    if generateRefreshToken:
        refresh_token = secrets.token_urlsafe(32)
    
    db.insert({
        'access_token': access_token,
        'client_id': client_id,
        'scope': ' '.join(scope),
        'user': user
    })
    
    if refresh_token:
        db.insert({
            'refresh_token': refresh_token,
            'client_id': client_id,
            'scope': ' '.join(scope),
            'user': user
        })

    print(f"Issuing access token {access_token}")
    if refresh_token:
        print(f"and refresh token {refresh_token}")
    print(f"with scope {scope}")

    cscope = ''
    if scope:
        cscope = ' '.join(scope)

    token_response = {
        'access_token': access_token,
        'token_type': 'Bearer',
        'refresh_token': refresh_token,
        'scope': cscope
    }

    return token_response

db.truncate()
