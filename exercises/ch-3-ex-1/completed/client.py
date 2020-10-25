from flask import Flask
from flask import render_template, redirect, request, session
import secrets, urllib.parse, base64, requests

app = Flask(__name__)

# need a secret key for session variables
app.secret_key = secrets.token_urlsafe(16)

# authorization server information
auth_server = {
  'authorization_endpoint': 'http://localhost:5001/authorize',
  'token_endpoint': 'http://localhost:5001/token'
}

# client information
client = {
  'client_id': 'oauth-client-1',
  'client_secret': 'oauth-client-secret-1',
  'redirect_uris': ['http://localhost:5000/callback']
}

protected_resource = 'http://localhost:5002/resource'

scope = ''

@app.route('/')
def index():
  if 'access_token' in session:
    return render_template('index.html', access_token=session['access_token'], scope=scope)
  else:
    return render_template('index.html', access_token='', scope='')

@app.route('/authorize')
def authorize():
  session['access_token'] = ''
  session['state'] = secrets.token_urlsafe(32)
    
  authorize_url = buildUrl(auth_server['authorization_endpoint'], {
    'response_type': 'code',
    'client_id': client['client_id'],
    'redirect_uri': client['redirect_uris'][0],
    'state': session['state']
  })

  return redirect(authorize_url)

@app.route('/callback')
def callback():
  if request.args.get('error', ''):
    return render_template('error.html', error=request.args.get('error', ''))

  if request.args.get('state', '') != session['state']:
    print(f"State DOES NOT MATCH: expected {session['state']} got {request.args.get('state','')}")
    return render_template('error.html', error="State value did not match")

  code = request.args.get('code', '')

  form_data = {
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': client['redirect_uris'][0]
  }
  headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': f"Basic {encodeClientCredentials(client['client_id'], client['client_secret'])}"
  }
  token_response = requests.post(auth_server['token_endpoint'], data=form_data, headers=headers)

  if token_response.status_code >= 200 and token_response.status_code < 300:
    body = token_response.json()
    session['access_token'] = body['access_token']
    print(f"Got access token: {session['access_token']}")
    return render_template('index.html', access_token=session['access_token'], scope=scope)
  else:
    return render_template('error.html', error=f"Unable to fetch access token, server response: {token_response.status_code}")
  
@app.route('/fetch_resource')
def fetch_resource():
  if not session['access_token']:
    return render_template('error.html', error="Missing Access Token")

  print(f"Making request with access token {session['access_token']}")

  headers = {
    'Authorization': f"Bearer {session['access_token']}"
  }
  resource = requests.post(protected_resource, headers=headers)

  if resource.status_code >= 200 and resource.status_code < 300:
    body = resource.json()
    return render_template('data.html', resource=body)
  else:
    session['access_token'] = ''
    return render_template('error.html', error=resource.status_code)

def buildUrl(base, options):
  url = urllib.parse.urlsplit(base)
  query_string = urllib.parse.urlencode(options)
  new_url = urllib.parse.urlunsplit((url.scheme, url.netloc, url.path, query_string, ""))
  return new_url

def encodeClientCredentials(client_id, client_secret):
  credentials = urllib.parse.quote(client_id, safe='') + ':' + urllib.parse.quote(client_secret, safe='')
  credentials_bytes = credentials.encode('ascii')
  credentials_b64 = base64.b64encode(credentials_bytes)
  return credentials_b64