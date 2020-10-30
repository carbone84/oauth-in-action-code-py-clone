from flask import Flask
from flask import render_template, redirect, request, session, url_for
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
  'redirect_uris': ['http://localhost:5000/callback'],
  'scope': 'foo'
}

protected_resource = 'http://localhost:5002/resource'
#session['state'] = ''
scope = ''
#session['access_token'] = '987tghjkiu6trfghjuytrghj'
#session['refresh_token'] = 'j2r3oj32r23rmasd98uhjrk2o3i'

@app.route('/')
def index():
  if not session.get('access_token'):
    session['access_token'] = '987tghjkiu6trfghjuytrghj'
    session['refresh_token'] = 'j2r3oj32r23rmasd98uhjrk2o3i'
  return render_template('index.html', access_token=session['access_token'], scope=scope, refresh_token=session['refresh_token'])

@app.route('/authorize')
def authorize():
  session['access_token'] = ''
  session['state'] = secrets.token_urlsafe(32)
  scope = ''
    
  authorize_url = buildUrl(auth_server['authorization_endpoint'], {
    'response_type': 'code',
    'scope': client['scope'],
    'client_id': client['client_id'],
    'redirect_uri': client['redirect_uris'][0],
    'state': session['state']
  })

  return redirect(authorize_url)

@app.route('/callback')
def callback():
  if request.args.get('error', ''):
    return render_template('error.html', error=request.args.get('error', ''))

  response_state = request.args.get('state', '')
  if response_state != session['state']:
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
      print(f"Got refresh token: {refresh_token}")
    scope = body['scope']
    print(f"Got scope: {scope}")
    return render_template('index.html', access_token=session['access_token'], scope=scope, refresh_token=session['refresh_token'])
  else:
    return render_template('error.html', error=f"Unable to fetch access token, server response: {token_response.status_code}")
  
@app.route('/fetch_resource')
def fetch_resource():
  if not session.get('access_token'):
    return render_template('error.html', error="Missing Access Token")

  print(f"Making request with access token {session['access_token']}")

  headers = {
    'Authorization': f"Bearer {session['access_token']}",
    'Content-Type': 'application/x-www-form-urlencoded'
  }
  resource = requests.post(protected_resource, headers=headers)

  if resource.status_code >= 200 and resource.status_code < 300:
    body = resource.json()
    return render_template('data.html', resource=body)
  else:
    session['access_token'] = ''
    if session.get('refresh_token'):
      return refreshAccessToken()
    else:
      return render_template('error.html', error=resource.status_code)

def refreshAccessToken():
  form_data = {
    'grant_type': 'refresh_token',
    'refresh_token': session['refresh_token']
  }
  headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': f"Basic {encodeClientCredentials(client['client_id'], client['client_secret'])}"
  }
  print(f"Refreshing token {session['refresh_token']}")
  token_response = requests.post(auth_server['token_endpoint'], data=form_data, headers=headers)
  if token_response.status_code >= 200 and token_response.status_code < 300:
    body = token_response.json()
    session['access_token'] = body['access_token']
    print(f"Got access token: {session['access_token']}")
    if body['refresh_token']:
      session['refresh_token'] = body['refresh_token']
      print(f"Got refresh token: {session['refresh_token']}")
    return redirect(url_for('fetch_resource'))
  else:
    print("No refresh token, asking the user to get a new access token")
    session['refresh_token'] = ''
    return render_template('error.html', error="Unable to refresh token.")

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