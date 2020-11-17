from flask import Flask
from flask import render_template, redirect, request, session, url_for
import secrets, urllib.parse, base64, requests

app = Flask(__name__)

# need a secret key for session variables
app.secret_key = secrets.token_urlsafe(16)

# authorization server information
auth_server = {
  'authorization_endpoint': 'http://localhost:5001/authorize',
  'token_endpoint': 'http://localhost:5001/token',
  'revocation_endpoint': 'http://localhost:5001/revoke',
  'registration_endpoint': 'http://localhost:50001/register',
  'userinfo_endpoint': 'http://localhost:5001/userinfo'
}

rsa_key = {
  'alg': 'RS256',
  'e': 'AQAB',
  'n': 'p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw',
  'kty': 'RSA',
  'kid': 'authserver'
}

# client information
client = {
  'client_id': 'oauth-client-1',
  'client_secret': 'oauth-client-secret-1',
  'redirect_uris': ['http://localhost:5000/callback'],
  'scope': 'foo bar'
}

protected_resource = 'http://localhost:5002/resource'

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
    'client_id': client['client_id'],
    'redirect_uri': client['redirect_uris'][0],
    'state': session['state'],
    'scope': client['scope']
  })
  print(f"redirect: {authorize_url}")
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
      print(f"Got refresh token: {session['refresh_token']}")
    session['scope'] = body.get('scope')
    print(f"Got scope: {session['scope']}")
    return render_template('index.html', access_token=session['access_token'], scope=session['scope'], refresh_token=session['refresh_token'])
  else:
    return render_template('error.html', error=f"Unable to fetch access token, server response: {token_response.status_code}")
  
@app.route('/refresh')
def refresh():
  form_data = {
    'grant_type': 'refresh_token',
    'refresh_token': session['refresh_token'],
    'client_id': client['client_id'],
    'client_secret': client['client_secret'],
    'redirect_uri': client['redirect_uris'][0]
  }
  print(f"form_data: {form_data}")
  headers = {'Content-Type': 'application/x-www-form-urlencoded'}
  print(f"Refreshing token {session['refresh_token']}")

  token_response = requests.post(auth_server['token_endpoint'], data=form_data, headers=headers)
  if token_response.status_code >= 200 and token_response.status_code <300:
    body = token_response.json()
    session['access_token'] = body['access_token']
    print(f"Got access token: {session['access_token']}")
    if body.get('refresh_token'):
      session['refresh_token'] = body['refresh_token']
      print(f"Got refresh token: {session['refresh_token']}")
    session['scope'] = body.get('scope')
    print(f"Got scope: {session['scope']}")
    return render_template('index.html', access_token=session['access_token'], refresh_token=session['refresh_token'], scope=session['scope'])
  else:
    print("No refresh token, asking the user to get a new access token")
    return render_template('index.html', access_token=session['access_token'], refresh_token=session['refresh_token'], scope=session['scope'])

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
    return render_template('error.html', error=f"Server returned response code: {resource.status_code}")

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