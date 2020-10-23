from flask import Flask
from flask import render_template

app = Flask(__name__)

resource = {
    "name": "Protected Resource",
    "description": "This data has been protected by OAuth 2.0"
}

@app.route('/')
def index():
    return render_template('index.html')