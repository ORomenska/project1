import os

from flask import Flask, session, render_template, request
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from argon2 import PasswordHasher
import argon2.exceptions

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"), pool_pre_ping=True)
db = scoped_session(sessionmaker(bind=engine))


@app.route("/")
def index():
    message="Welcome to eLit! Please use a form below to log in."
    return render_template("index.html",message=message)
@app.route("/login",methods=["POST"])
def login():
    message=""
    site_login=request.form.get("site_login")
    password=request.form.get("password")
    result=db.execute("SELECT password,visible_name FROM users WHERE login=:login",{"login": site_login}).fetchone()

    if result is None:
        message="Login or password is incorrect. Please try again."
        return render_template("index.html",message=message)

    for row in result:
        password_hash=row[0]
        name=row[1]
    try:
        pwd_hasher = PasswordHasher()
        pwd_hasher.verify(password_hash, password)
    except argon2.exceptions.VerifyMismatchError:
        message="Login or password is incorrect. Please try again."
        return render_template("index.html",message=message)
    except:
        message="An error has occured during authentication. Please try again."
        return render_template("index.html",message=message)
    session['login']=site_login
    return redirect(url_for('homepage'))
@app.route("/registration-page")
def registration_page():
    message="Please fill the form below to register"
    return render_template("register.html")
@app.route("/register",methods=["POST"])
def register():
    site_login=request.form.get("site_login")
    visible_name=request.form.get("visible_name")
    password=request.form.get("password")
    password_retype=request.form.get("password_retype")
    error_message=""
    if len(site_login)==0:
        error_message="* Login can't be empty"
        return render_template("register.html",error_message=error_message)
    elif len(visible_name)==0:
        error_message="* Visible name can't be empty"
        return render_template("register.html",error_message=error_message)
    elif (len(password)==0) or (len(password_retype)==0):
        error_message="* Please fill both password fields"
        return render_template("register.html",error_message=error_message)
    elif (len(password)<8) or (len(password_retype)<8):
        error_message="* Password must be at least 8 characters long"
        return render_template("register.html",error_message=error_message)
    elif password != password_retype:
        error_message="* Passwords don't match"
        return render_template("register.html",error_message=error_message)
    try:
        result=db.execute("SELECT password,visible_name FROM users WHERE login=:login",{"login": site_login}).fetchone()
    except:
        error_message="An error ocured during registartion. Please try later"
        return render_template("register.html",error_message=error_message)

    if result is not None:
        error_message="Please use another login(email)"
        return render_template("register.html",error_message=error_message)
        
    pwd_hasher = PasswordHasher()
    hashed_password = pwd_hasher.hash(password)
    try:
        db.execute("INSERT INTO users(login,password,visible_name) VALUES (:login,:password,:visible_name)",{"login":site_login,"password":hashed_password,"visible_name":visible_name})
        db.commit()
    except:
        db.rollback()
        db.close()
        error_message="An error ocured during registartion. Please try later"
        return render_template("register.html",error_message=error_message)
    db.close()
    return render_template("success.html",visible_name=visible_name)
@app.route("/home",methods="GET")
def homepage():
    pass



