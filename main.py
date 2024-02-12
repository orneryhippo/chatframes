from flask import Flask, render_template, request, redirect, url_for,jsonify, session 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_login import current_user
from flask_cors import CORS, cross_origin
from flask_bcrypt import Bcrypt
import httpx
import requests 
from pprint import pprint as pp
from icecream import ic 
from datetime import datetime 
import prompts
from dotenv import load_dotenv
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

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

load_dotenv()
openai_api_key = os.getenv("OPENAI_API_KEY","")
ic(openai_api_key)
API_PW = os.getenv("API_PW")

# Dummy user database
users = {'jesse@cassill.work': {'password': 'fubar999!!!'}}

SYSTEM_PROMPT = prompts.DFB_PROMPT

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    # Your logic to return a user object given the user_id
    return getUserById(user_id)  # Replace with your user retrieval logic


@login_manager.user_loader
def user_loader(email):
    if email not in users:
        return

    user = User()
    user.id = email
    return user

def _get_xano_token():
    auth_url = "https://x8ki-letl-twmt.n7.xano.io/api:KPiD297b/auth/login"
    user_id = "api@quantadata.us"
    password = API_PW
    # logging.debug(API_PW)

    HEADERS = {
        "Content-Type":"application/json"
    }
    data = {
        "email":user_id,
        "password":password 
    }
    response = requests.post(auth_url, json=data, headers=HEADERS)
    if response.status_code == 200:
        data = response.json()
        # logging.debug(data)
        token = data['authToken']
        # logging.debug(token)     

        return token
    else:
        logging.error(f"Error: {response.status_code}, {response.content}")
        return ''

@app.route('/')
def index():
    return render_template('waitlist-ai.html')

@app.route("/chatzone")
def chatzone():
    return render_template('chatzones.html')

@app.route("/askdfb", methods = ["POST","GET"])
def askdfb():
    return render_template('askdfb.html')

@app.route("/submit", methods=["POST"])
def submit_question():
    token=_get_xano_token()
    API_KEY=token
    # Define the headers for the HTTP request
    HEADERS = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    logging.debug(HEADERS)
    XANU_DFB_QUESTIONS = "https://x8ki-letl-twmt.n7.xano.io/api:KPiD297b/dfb_questions"
    MAKE_WEBHOOK = 'https://hook.us1.make.com/hi3vyd5f0f7k0tnh11uyd6ib2w05ks28'
    user_id = request.form['email']
    question = request.form['question']
    data = {
        "user_id": user_id,
        "question": question
    }
    logging.debug(data)
    # response = requests.post(XANU_DFB_QUESTIONS, json=data, headers=HEADERS)
    response = requests.post(MAKE_WEBHOOK, json=data, headers=HEADERS)
    if(response.status_code == 200):
        return render_template('success.html',data=data)
    else:
        error_message = f"Error Code: {response.status_code}, Message: {response.text}"
        return render_template('error.html', error_message=error_message)
        
        

@app.route('/klaven',methods=['GET'])
def klaven():
    return render_template('klaven.html')



@app.route('/ask', methods=['POST'])
@cross_origin()
def ask_openai():
    # if 'messages' not in session: 
    #     session['messages'] = [{"role": "system", "content": SYSTEM_PROMPT}] 
    # ic(session['messages'])
    question = request.json.get('question')
    # session['messages'].append({"role": "user", "content": question})
    api_key = request.json.get('api-key',openai_api_key)
    api_key = openai_api_key
    ic(api_key)
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    # ic(headers)
    data = {
        'model': 'gpt-4-0125-preview',  # Specify the GPT model you are using 'gpt-3.5-turbo', #
        'messages': [{"role": "system", "content": SYSTEM_PROMPT},{"role": "user", "content": question}]
    }
    # ic(data)
    # response = httpx.post('https://api.openai.com/v1/chat/completions', headers=headers, json=data)
    response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=data)
    ic(response)
    if response.status_code == 200:
        completion = response.json()
        ic(completion)
        reply = completion['choices'][0]['message']['content']
        ic(reply)
       

        # session['messages'].append({"role": "agent", "content": reply})
        # pp(completion)
        # return jsonify(reply), 200
        return render_template('chatzones.html')
    
    return jsonify({'error': 'Could not get a response from the OpenAI API'}), response.status_code



@app.route('/register', methods=['POST','GET'])
def register():
    MSG = request.args.get('message',None) if request.method == 'GET' else request.form.get('message',None)

    if request.method == 'GET':
        ic(MSG)
        if MSG is not None:
            return render_template('register.html',message=MSG)
        else:
            return render_template('register.html', message=MSG)
        
    user_id = request.form['email']
    plain_password = request.form['password']

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(plain_password).decode('utf-8')
    # ic(hashed_password)
    # Store user_id and hashed_password in your Xano database
    store_user_url = "https://x8ki-letl-twmt.n7.xano.io/api:KPiD297b/simple_login"
    # ...
    HEADERS = {}
    BODY = {"user_id": user_id, "password":hashed_password}
    response  = httpx.post(store_user_url, headers=HEADERS, json=BODY)
    data = response.json()
    ic(data)
    if response.status_code == 200 and data.get('user_created',None) is not None:
        # return 'User registered successfully', response.status_code
        return redirect(url_for('login', message="User Registered Successfully. Please Log In."))
    else:
        return redirect(url_for('register', message="User Already Exists"))

@app.route('/login', methods=['POST','GET'])
def login():
    try:
        if request.method == 'GET':
            return render_template('login.html')
        
        login_id = request.form['email']
        plain_password = request.form['password']
        # Retrieve the hashed password from your Xano database based on user_id
        # https://x8ki-letl-twmt.n7.xano.io/api:KPiD297b/simple_login/{simple_login_id}
        get_user_url = f"https://x8ki-letl-twmt.n7.xano.io/api:KPiD297b/simple_login_by_id?login_id={login_id}"
        HEADERS={}
        BODY={}
        response = httpx.get(get_user_url,headers=HEADERS)
        ic(response.status_code)
        stored_hashed_password = ""
        if (response.status_code == 200):
            response_records = response.json()
            if len(response_records) == 1:
                user_record = response_records[0]
                stored_hashed_password = user_record.get('password',"")
        # Let's assume you get it in a variable `stored_hashed_password`
        # ...

        # Verify the password
        if bcrypt.check_password_hash(stored_hashed_password, plain_password):
            ic('Login successful')
            return render_template('askdfb.html',user=user_record.get('user_id',""))
        else:
            ic('Invalid user ID or password')
            return render_template('login.html', message="Invalid Login")
    except Exception as e:
        ic(e)



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