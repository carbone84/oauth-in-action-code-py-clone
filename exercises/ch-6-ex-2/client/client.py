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
}

# client information
client = {
  'client_id': 'oauth-client-1',
  'client_secret': 'oauth-client-secret-1',
  'scope': 'foo bar'
}

protected_resource = 'http://localhost:5002/resource'

@app.route('/')
def index():
  session['access_token'] = ''
  session['scope'] = ''
  return render_template('index.html', access_token=session['access_token'], scope=session['scope'])

@app.route('/authorize')
def authorize():
  session['access_token'] = ''
  session['scope'] = ''
  
  #
  # Implement the client credentials flow here
  #

  return render_template('index.html', access_token=session['access_token'], scope=session['scope'])

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

def encodeClientCredentials(client_id, client_secret):
  credentials = urllib.parse.quote(client_id, safe='') + ':' + urllib.parse.quote(client_secret, safe='')
  credentials_bytes = credentials.encode('ascii')
  credentials_b64 = base64.b64encode(credentials_bytes)
  return credentials_b64