from flask import Flask
from flask import render_template, redirect, request, session
import secrets, urllib.parse, base64, requests

app = Flask(__name__)

# need a secret key for session variables
app.secret_key = secrets.token_urlsafe(16)

# authorization server information
auth_server = {
  'authorization_endpoint': 'http://localhost:5001/authorize',
  'token_endpoint': 'http://localhost:5001/token',
  'revocation_endpoint': 'http://localhost:5001/revoke',
  'registration_endpoint': 'http://localhost:5001/register',
  'userinfo_endpoint': 'http://localhost:5001/userinfo'
}

# client information
client = {
  'client_id': 'oauth-client-1',
  'client_secret': 'oauth-client-secret-1',
  'redirect_uris': ['http://localhost:5000/callback'],
  'scope': 'fruit veggies meats'
}

produce_api = 'http://localhost:5002/produce'


@app.route('/')
def index():
  session['state'] = ''
  session['access_token'] = ''
  session['refresh_token'] = ''
  session['scope'] = ''
  return render_template('index.html', access_token=session['access_token'], scope=session['scope'], refresh_token=session['refresh_token'])

@app.route('/authorize')
def authorize():
  session['access_token'] = ''
  session['refresh_token'] = ''
  session['state'] = secrets.token_urlsafe(32)
  session['scope'] = ''
    
  authorize_url = buildUrl(auth_server['authorization_endpoint'], {
    'response_type': 'code',
    'scope': client['scope'],
    'client_id': client['client_id'],
    'redirect_uri': client['redirect_uris'][0],
    'state': session['state']
  })
  print(f"redirect: {authorize_url}")
  return redirect(authorize_url)

@app.route('/callback')
def callback():
  if request.args.get('error', ''):
    return render_template('error.html', error=request.args.get('error', ''))

  response_state = request.args.get('state', '')
  if response_state == session['state']:
    print(f"State value matches: expected {session['state']} got {response_state}")
  else:
    print(f"State DOES NOT MATCH: expected {session['state']} got {response_state}")
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
  print(f"Requesting access token for code {code}")

  if token_response.status_code >= 200 and token_response.status_code < 300:
    body = token_response.json()
    session['access_token'] = body['access_token']
    print(f"Got access token: {session['access_token']}")
    if body.get('refresh_token'):
      session['refresh_token'] = body['refresh_token']
      print(f"Got refresh token: {session['refresh_token']}")
    session['scope'] = body['scope']
    print(f"Got scope: {session['scope']}")
    return render_template('index.html', access_token=session['access_token'], scope=session['scope'], refresh_token=session['refresh_token'])
  else:
    return render_template('error.html', error=f"Unable to fetch access token, server response: {token_response.status_code}")
  
@app.route('/produce')
def produce():
  headers = {
    'Authorization': 'Bearer ' + session['access_token'],
    'Content-Type': 'application/x-www-form-urlencoded'
  }

  resource = requests.get(produce_api, headers=headers)

  if resource.status_code >= 200 and resource.status_code < 300:
    body = resource.json()
    print(f"body {body}")
    print(f"access_token {session['access_token']}")
    print(f"scope {session['scope']}")
    return render_template('produce.html', scope=session['scope'], data=body)
  else:
    return render_template('produce.html', scope=session['scope'], data={'fruits': [], 'veggies': [], 'meats': []})

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