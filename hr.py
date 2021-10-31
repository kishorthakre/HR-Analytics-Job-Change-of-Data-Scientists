

from flask import Flask, request, session, redirect, url_for, render_template, flash
import psycopg2
import psycopg2.extras
import pickle
import numpy as np
import re
from werkzeug.security import generate_password_hash, check_password_hash

connc = psycopg2.connect(database="postgres", user='postgres', password='KishorP58', host='127.0.0.1', port= '5432')
cursor = connc.cursor(cursor_factory=psycopg2.extras.DictCursor)
cursor.execute('drop table if exists users')
cursor.execute('create table users (id serial primary key, fullname varchar(100) not null, username varchar(50) not null, password varchar(255) not null, email varchar(50) not null);')
connc.commit()
connc.close()


app = Flask(__name__)
app.secret_key = 'cairocoders-ednalan'
model = pickle.load(open('Decitmodel.pkl', 'rb'))
le_gender = pickle.load(open('Lencoder_gender.pkl', 'rb'))
le_revexp = pickle.load(open('Lencoder_rev_exp.pkl', 'rb'))
le_enr_uni = pickle.load(open('Lencoder_enr_uni.pkl', 'rb'))
le_mjr_dis = pickle.load(open('Lencoder_mjr_dis.pkl', 'rb'))
le_cmp_type = pickle.load(open('Lencoder_cmp_type.pkl', 'rb'))



DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASS = "KishorP58"


conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

@app.route('/',methods = ['GET','POST'])
def home():
    # Check if user is loggedin
    print(session)
    if 'loggedin' in session:

        # User is loggedin show them the home page
        return render_template('home.html',username=session['username'] )
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        print(password)

        # Check if account exists using PostgreSQL
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        # Fetch one record and return result
        account = cursor.fetchone()

        if account:
            password_rs = account['password']
            print(password_rs)
            # If account exists in users table in out database
            if check_password_hash(password_rs, password):
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                # Redirect to home page
                return redirect(url_for('home'))
            else:
                # Account doesnt exist or username/password incorrect
                flash('Incorrect username/password')
        else:
            # Account doesnt exist or username/password incorrect
            flash('Incorrect username/password')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        _hashed_password = generate_password_hash(password)

        # Check if account exists using MySQL
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        print(account)
        # If account exists show error and validation checks
        if account:
            flash('Account already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not username or not password or not email:
            flash('Please fill out the form!')
        else:
            # Account doesnt exists and the form data is valid, now insert new account into users table
            cursor.execute("INSERT INTO users (fullname, username, password, email) VALUES (%s,%s,%s,%s)", (fullname, username, _hashed_password, email))
            conn.commit()
            flash('You have successfully registered!')
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        flash('Please fill out the form!')
    # Show registration form with message (if any)
    return render_template('register.html')


@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if user is loggedin
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM users WHERE id = %s', [session['id']])
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/predict', methods=['POST'])
def predict():
    education_level_Dict = {'Primary School': 1, 'High School': 2, 'Graduate': 3, 'Masters': 4, 'Phd': 5}

    list1=list(dict(request.form).values())
    # print(list1)

    encoded_gender = (le_gender.transform(np.array([list1[1]])))[0]
    encoded_rev_exp = (le_revexp.transform(np.array([list1[2]])))[0]
    encoded_enr_uni = (le_enr_uni.transform(np.array([list1[3]])))[0]
    encoded_educ_lvl = education_level_Dict[list1[4]]
    encoded_mjr_dis = (le_mjr_dis.transform(np.array([list1[5]])))[0]
    encoded_cmp_type = (le_cmp_type.transform(np.array([list1[8]])))[0]
    features =[list1[0], encoded_gender, encoded_rev_exp, encoded_enr_uni, encoded_educ_lvl,encoded_mjr_dis,list1[6],list1[7], encoded_cmp_type,list1[9],list1[10]]
    final_features = np.array(features)
    # print(final_features)

    prediction = model.predict([final_features])
    pred = round(prediction[0], 2)
    if pred == 0:
        output = 'No'
    else:
        output = 'Yes'

    return render_template('home.html', prediction_text='Looking for job change ---> {}'.format(output))

if __name__ == "__main__":
    app.run(debug=True)



