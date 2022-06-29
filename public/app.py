import json
import sqlite3
import re
import requests
from flask import Flask, session, redirect, request, render_template, flash
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps


# Prepare app for Flask
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def welcome():
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            db = sqlite3.connect('moviender.db')
        except Exception as e:
            flash("DB error")
            return render_template("./register.html")
        cur = db.cursor()
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username or not password or not confirmation:
            flash("Please fill out the form!")
            return render_template("./register.html")
        cur.execute("SELECT * FROM users WHERE username = ?", [username])
        check = cur.fetchone()
        if check:
            flash("Username already exists")
            return render_template("./register.html")
        elif re.compile('[^0-9a-zA-Z]+').search(username):
            flash("Username must contain only characters and numbers!")
            return render_template("./register.html")
        elif not password == confirmation:
            flash("Passwords not match")
            return render_template("./register.html")
        # Generate password hash
        else:
            hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
            cur.execute("INSERT INTO users VALUES (NULL, ?, ?, DATE())", (username, hash))
            db.commit()
            flash("Registration is successful")
            return redirect("/")
    else:
        return render_template("./register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            flash("Please fill out the form!")
            return render_template("./login.html")
        elif not request.form.get("password"):
            flash("Please fill out the form!")
            return render_template("./login.html")
        try:
            db = sqlite3.connect('moviender.db')
        except Exception as e:
            flash("DB error")
            return render_template("./login.html")
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", [request.form.get("username")])
        rows = cur.fetchone()
        if not rows:
            flash("Invalid username")
            return render_template("./login.html")
        hash = rows[2]
        if not check_password_hash(hash, request.form.get("password")):
            flash("Invalid password")
            return render_template("./login.html")
        session["user_id"] = rows[0]
        db.close()
        return redirect("/")
    else:
        return render_template("./login.html")
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        if request.form.get('favor') == 'id':
            data = request.form.get('index')
            try:
                db = sqlite3.connect('moviender.db')
            except Exception as e:
                flash("DB error")
                return redirect("/profile")
            cur = db.cursor()  
            cur.execute("SELECT * FROM favor WHERE userID = ? AND titleID = ?", (session["user_id"], data))
            check = cur.fetchone()
            if check:
                flash("Already in favourite")
                return redirect("/profile")
            cur.execute("INSERT INTO favor (userID, titleID) VALUES (?, ?)", (session["user_id"], data))
            db.commit()
            flash("Added to favourite")
            return redirect("/profile")
        elif request.form.get('unfavor') == 'unid':
            data = request.form.get('index')
            try:
                db = sqlite3.connect('moviender.db')
            except Exception as e:
                flash("DB error")
                return redirect("/profile")
            cur = db.cursor()  
            cur.execute("DELETE FROM favor WHERE titleID = ?", (data,))
            db.commit()
            flash("Removed from favourite")
            return redirect("/profile")
    else:
        try:
            db = sqlite3.connect('moviender.db')
        except Exception as e:
            flash("DB error")
            return redirect("/profile")
        cur = db.cursor()
        cur.execute("SELECT titleID FROM favor WHERE userID = ?", (session["user_id"],))
        fav = cur.fetchall()
        data = []
        for i in fav:
            tmp = profile(i[0])
            data.append(tmp.json())
        cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
        tmp = cur.fetchone()
        dataID = tmp
        db.close()
        return render_template("./profile.html", data=data, dataID=dataID)

@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "POST":
        keyword = request.form.get("keyword")
        if not request.form.get("keyword"):
            flash("Please put some keyword!")
            tmp = moviesstart()
            data = tmp.json()
            return render_template("./search.html", data=data["results"])
        elif re.compile('[^0-9a-zA-Z" "]+').search(keyword):
            flash("Use only characters and numbers!")
            tmp = moviesstart()
            data = tmp.json()
            return render_template("./search.html", data=data["results"])
        elif not request.form.get("year"):
            year = 0
        else:
            year = request.form.get("year")
        type = request.form.get("Type")
        tmp = movies(keyword, type, year)
        data = tmp.json()
        return render_template("./search.html", data=data["results"])
    else:
        tmp = moviesstart()
        data = tmp.json()
        return render_template("./search.html", data=data["results"])
    
@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        opassword = request.form.get("opassword")
        npassword = request.form.get("npassword")
        confirmation = request.form.get("confirmation")

        if not opassword:
            flash("Must provide old password")
            return redirect("/change")
        elif not npassword:
            flash("Must provide new password")
            return redirect("/change")
        elif not npassword == confirmation:
            flash("Passwords not match")
            return redirect("/change")
        else:
            try:
                db = sqlite3.connect('moviender.db')
            except Exception as e:
                flash("DB error")
                return redirect("/change")
            cur = db.cursor()  
            cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
            tmp = cur.fetchone()
            if not check_password_hash(tmp[2], opassword):
                flash("Invalid old password")
                return redirect("/change")
            else:
                hash = generate_password_hash(npassword, method="pbkdf2:sha256", salt_length=8)
                cur.execute("UPDATE users SET hash = ? WHERE id = ? ", (hash, session["user_id"],))
                db.commit()
                flash("Password is changed")
                return redirect("/profile")
    else:
        return render_template("change.html")
        

def movies(keyword, type, year):
    url = f"https://moviesdatabase.p.rapidapi.com/titles/search/title/{keyword}"
    if year == 0:
        querystring = {"info":"base_info","limit":"25","page":"1","titleType":type,"sort":"year.decr"}
    else:
        querystring = {"info":"base_info","limit":"25","page":"1","titleType":type,"year":year,"sort":"year.decr"}
    headers = {"X-RapidAPI-Key": "f159110cabmsh36ef0b49c0789cap19235cjsn9c92c606b607",
	"X-RapidAPI-Host": "moviesdatabase.p.rapidapi.com"}
    response = requests.request("GET", url, headers=headers, params=querystring)
    return response

def moviesstart():
    url = "https://moviesdatabase.p.rapidapi.com/titles/x/upcoming"
    querystring = {"info":"base_info","limit":"10","page":"1","titleType":"movie"}
    headers = {"X-RapidAPI-Key": "f159110cabmsh36ef0b49c0789cap19235cjsn9c92c606b607",
	"X-RapidAPI-Host": "moviesdatabase.p.rapidapi.com"}
    response = requests.request("GET", url, headers=headers, params=querystring)
    return response

def profile(id):
    url = f"https://moviesdatabase.p.rapidapi.com/titles/{id}"
    querystring = {"info":"base_info"}
    headers = {"X-RapidAPI-Key": "f159110cabmsh36ef0b49c0789cap19235cjsn9c92c606b607",
	"X-RapidAPI-Host": "moviesdatabase.p.rapidapi.com"}
    response = requests.request("GET", url, headers=headers, params=querystring)
    return response
