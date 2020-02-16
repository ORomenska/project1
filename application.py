import os

from flask import Flask, session, render_template, request, redirect, url_for, make_response
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from argon2 import PasswordHasher
import argon2.exceptions
from configparser import ConfigParser
import requests
import json
import jwt
import datetime

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
    result=db.execute("SELECT password,visible_name,user_id FROM users WHERE login=:login",{"login": site_login}).fetchone()
    

    ### users table schema
    ###  user_id | login | password | visible_name

    if result is None:
        message="Login or password is incorrect. Please try again."
        return render_template("index.html",message=message)
    
    password_hash=result[0]
    message=password_hash
    visible_name=result[1]
    user_id=result[2]
    try:
        pwd_hasher = PasswordHasher()
        pwd_hasher.verify(password_hash, password)
    except argon2.exceptions.VerifyMismatchError:
        message="Login or password is incorrect. Please try again."
        return render_template("index.html",message=message)
    except:
        message="An error has occured during authentication. Please try again."
        return render_template("index.html",message=message)
    session['site_login']=site_login
    session['visible_name']=visible_name
    session['user_id']=user_id
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
# Checking user registration conventions
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
        error_message="An error ocured during registration. Please try later"
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
    
    return render_template("success.html",visible_name=visible_name)
@app.route("/home",methods=["GET"])
def homepage():
    if 'site_login' in session:
        site_login=session['site_login']
        visible_name=session['visible_name']
        return render_template("homepage.html",site_login=site_login,visible_name=visible_name)
    else:
        return redirect(url_for('index'))
@app.route("/search",methods=["POST"])
def search():
    if 'site_login' in session:
        site_login = session['site_login']
        visible_name = session['visible_name']
        search_text = request.form.get('search_text')
        select = str(request.form.get('search_type'))
        result=""
# Selecting data from DB based on search criterion
        ### books table schema
        ### isbn | title | author | year 
        if select == "by_isbn" and search_text:
            if search_text.isdigit():
                search_text_str=str(search_text)
                try:
                    result=db.execute("SELECT * FROM books WHERE isbn LIKE :search_text_str",{"search_text_str":"%"+ search_text_str + "%"}).fetchall()
                except Exception as e:
                    result="ERROR" + str(e)
            else:
                try:
                    result=db.execute("SELECT * FROM books WHERE isbn LIKE :search_text",{"search_text":"%"+ search_text + "%"}).fetchall()
                except Exception as e:
                    result="ERROR" + str(e)

        elif select == "by_title" and search_text:
            if search_text.isdigit():
                search_text_str=str(search_text)
                try:
                    result=db.execute("SELECT * FROM books WHERE title LIKE :search_text_str",{"search_text_str":"%"+ search_text_str + "%"}).fetchall()
                except Exception as e:
                    result="ERROR" + str(e)
            else:
                try:
                    result=db.execute("SELECT * FROM books WHERE title LIKE :search_text", {"search_text":"%" + search_text + "%"}).fetchall()
                except Exception as e:
                    result="ERROR" + str(e)

        elif select == "by_author" and search_text:
            if search_text.isdigit():
                search_text_str=str(search_text)
                try:
                    result=db.execute("SELECT * FROM books WHERE author LIKE :search_text_str",{"search_text_str":"%"+ search_text_str + "%"}).fetchall()
                except Exception as e:
                    result="ERROR" + str(e)
            else:
                try:
                    result=db.execute("SELECT * FROM books WHERE author LIKE :search_text", {"search_text":"%" + search_text + "%"}).fetchall()
                except Exception as e:
                    result="ERROR" + str(e)
  
###!!!! ADD HANDLING ERRORS AND PARSING APPROPRITE DATA TO A TEMPLATE!!!!!!
###Checking results
        return render_template("search-results.html", result=result, search_text=search_text, visible_name = visible_name, select=select)
    else:
        return redirect(url_for('index'))

@app.route("/book-info/<isbn>")
def book_info(isbn):
    ###Obtaining info from site DB
    if 'site_login' in session:
        site_login = session['site_login']
        visible_name = session['visible_name']
        user_id = session['user_id']
        book_db_info=""
        try:
            book_db_info=db.execute("SELECT * FROM books WHERE isbn = :isbn",{"isbn": str(isbn)}).fetchone()
        except Exception as e:
            book_db_info="ERROR"
            error_info = str(e)
    ###Obtaining info from GoodReads API
        goodreads_info=()
        config_path = os.getcwd() + "/creds/goodreadsAPI.config"
        parser = ConfigParser()
        parser.read(config_path)
        api_key = parser["DEFAULT"]["key"]
        headers = {"Accept" : "application/json"}
        payload = {"isbns": str(isbn), "key" : api_key}
        response = requests.get("https://www.goodreads.com/book/review_counts.json", payload)
        if response.status_code == 200:
            response_content = json.loads(response.content)
            goodreads_ratings_count = str(response_content["books"][0]["work_ratings_count"])
            goodreads_avg_rating = str(response_content["books"][0]["average_rating"])
            goodreads_info=(goodreads_ratings_count,goodreads_avg_rating)
#        return render_template("book-info.html",local_result = local_result, goodreads_result = goodreads_result)
        else:
            goodreads_result = ("NA","NA")
#        return render_template("book-info.html",local_result = local_result, goodreads_result = ("NA","NA"))
        book_reviews=""
        try:
            book_reviews=db.execute("SELECT users.visible_name,reviews.review,reviews.rating FROM reviews INNER JOIN users ON (reviews.user_id = users.user_id) WHERE reviews.isbn = :isbn ",{"isbn": isbn}).fetchall()
        except Exception as e:
            book_reviews="ERROR"
            error_info = str(e)
        
        return render_template("book-info.html",book_db_info = book_db_info, goodreads_info = goodreads_info, book_reviews = book_reviews, visible_name = visible_name)
    else:
        return redirect(url_for('index'))




@app.route("/submit-review/<isbn>",methods=["POST"])
def submit_review(isbn):
    if 'site_login' in session:
        site_login = session['site_login']
        visible_name = session['visible_name']
        user_id = session['user_id']
        review_text = request.form.get('review_text')
        rating = request.form.get('rating')

        ### reviews table schema
        ###  isbn | user_id | review | rating
        ###### CHECK INTERACTIONS WITH DB!!!!!!!
        try:
            result = db.execute("SELECT * FROM reviews WHERE user_id=:user_id AND isbn=:isbn",{"user_id":user_id,"isbn":isbn}).fetchall()
            if result:
                return redirect(url_for('book_info',isbn=isbn))
            else:
                db.execute("INSERT INTO reviews(isbn,user_id,review,rating) VALUES (:isbn,:user_id,:review,:rating)",{"isbn":isbn,"user_id":user_id,"review":review_text,"rating":rating})
                db.commit()
        except:
            db.rollback()
            db.close()
        
        return redirect(url_for('book_info',isbn=isbn))
    else:
        return redirect(url_for('index'))
@app.route("/get-token")
def get_token():
    error_message=""
    if 'site_login' in session:
        site_login = session['site_login']
        """
        Generates the Auth Token
        :return: string
        """
        config_path = os.getcwd() + "/creds/jwt.config"
        parser = ConfigParser()
        parser.read(config_path)
        secret = parser["JWT"]["secret"]
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=60, seconds=0),
                'iat': datetime.datetime.utcnow(),
                'sub': site_login
            }
            token = jwt.encode(payload, secret,algorithm='HS256')
        except Exception as e:
            error_message="Cannot create token"
            response = make_response({"Message" : error_message})
            return response,500
        response = make_response({"Auth-token" : token.decode("utf-8")})
        return response,201
    else:
        return redirect(url_for('index')),302
        

@app.route("/api/<isbn>",methods=["GET"])
def api(isbn):
    auth_token = request.args.get('Auth-token')
    config_path = os.getcwd() + "/creds/jwt.config"
    parser = ConfigParser()
    parser.read(config_path)
    secret = parser["JWT"]["secret"]
    error_message = ""
    login_check=""
    review_count = 0
    rating_avg = 0

    try:
        payload = jwt.decode(auth_token, secret)
        login = payload['sub']
    except jwt.ExpiredSignatureError:
        error_message = 'Signature expired. Please log in again.'
        response = make_response({"Message" : error_message})
        return response,403
    except jwt.InvalidTokenError:
        response = make_response({"Message" : error_message})
        return response,403
    try:
        login_check=db.execute("SELECT * FROM users WHERE login=:login",{"login": login}).fetchone()
        if login_check:
            try:
                is_exists = db.execute("SELECT FROM books WHERE isbn = :isbn", {"isbn":isbn}).fetchall()
                if is_exists:
                    result  = db.execute("SELECT COUNT(*) FROM reviews WHERE isbn = :isbn", {"isbn":isbn}).fetchone()
                    review_count = result[0]
                    result = db.execute("SELECT SUM(rating) FROM reviews WHERE isbn = :isbn", {"isbn":isbn}).fetchone()
                    rating_avg = float(result[0])/review_count
                    rating_avg = '{:{width}.{prec}f}'.format(rating_avg, width=4, prec=2)
                    response = make_response({ "message": {"isbn" : isbn, "review_count" : review_count, "Average rating" : rating_avg if rating_avg else 0 }})
                    return response,200
                else:
                    response = make_response({ "message": "404 Not found"})
                    return response,404
            except:
                error_message = "Error in DB connection"
                response = make_response({"Message" : error_message})
                return response,500
        else:
            error_message = "Not authorized"
            response = make_response({"Message" : error_message})
            return response,403
    except:
        error_message = "Internal server error. Please try again later"
        response = make_response({"Message" : error_message})
        return response,500
    




@app.route("/logout")
def logout():
    session.pop('site_login',None)
    session.pop('visible_name',None)
    return redirect(url_for('index'))


