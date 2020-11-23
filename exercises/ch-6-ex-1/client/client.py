from flask import Flask
from flask import render_template, redirect, request, session, url_for
import secrets, urllib.parse, base64, requests

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
  return render_template('index.html')