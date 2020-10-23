from flask import Flask
from flask import render_template, redirect, request, session
import secrets, urllib.parse, base64 #, requests

app = Flask(__name__)

app.secret_key = secrets.token_urlsafe(16)

# authorization server information
auth_server = {
  'authorization_endpoint': 'http://localhost:5001/authorize',
  'token_endpoint': 'http://localhost:5001/token'
}

# client information
client = {
  'client_id': '',
  'client_secret': '',
  'redirect_uris': ['http://localhost:5000/callback']
}

protected_resource = 'http://localhost:5002/resource'

state = ''
access_token = '' 
scope = ''

@app.route('/')
def index():
  return render_template('index.html', access_token=access_token, scope=scope)

@app.route('/authorize')
def authorize():
  #
  # Send the user to the authorization server
  #
  return render_template('')

@app.route('/fetch_resource')
def fetch_resource():
  #
  # Use the access token to call the resource server
  #
  return render_template('')

#TODO
#def buildUrl():

def encodeClientCredentials(client_id, client_secret):
  credentials = urllib.parse.quote(client_id, safe='') + ':' + urllib.parse.quote(client_secret, safe='')
  credentials_bytes = credentials.encode('ascii')
  credentials_b64 = base64.b64encode(credentials_bytes)
  return credentials_b64