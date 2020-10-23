from flask import Flask
from flask import render_template

app = Flask(__name__)

access_token = ""
refresh_token = ""
scope = ""

@app.route('/')
def index():
  return render_template('index.html', access_token=access_token, refresh_token=refresh_token, scope=scope)