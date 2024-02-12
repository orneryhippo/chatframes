from flask import Flask, render_template, request, redirect, url_for,jsonify, session 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_login import current_user
from flask_cors import CORS, cross_origin
from flask_bcrypt import Bcrypt
import httpx
import requests 
from datetime import datetime 
import os
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.debug('Debug message')
logging.info('Informational message')
logging.warning('Warning message')
logging.error('Error message')
logging.critical('Critical message')

app = Flask(__name__)
app.secret_key = os.urandom(32)
bcrypt = Bcrypt(app)
CORS(app)

@app.route('/')
def index():
    return render_template('waitlist-ai.html')

@app.route("/chatzone")
def chatzone():
    return render_template('chatzones.html')


@app.route('/klaven',methods=['GET'])
def klaven():
    return render_template('klaven.html')




# bogus replit stuff
@app.route('/srcdoc')
def srcdoc():
  return redirect(url_for('index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/protected')
@login_required
def protected():
    ic(current_user.id)
    now = datetime.now()
    ic(now.timestamp())
    return render_template('protected.html')
    # return 'Logged in as: ' + current_user.get_id()

if __name__ == '__main__':
    
    app.run(debug=True, host='0.0.0.0', port=81)