from flask import Flask
from flask import render_template

app = Flask(__name__)

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
        "client_id": "oauth-client-1",
        "client_secret": "oauth-client-secret-1",
        "redirect_uris": ["http://localhost:5000/callback"],
        "scope": "foo bar"
    }
]

@app.route('/')
def index():
    return render_template('index.html', clients=clients, auth_server=auth_server)