from flask import Flask, render_template, url_for, flash, redirect, request, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
import pymysql
from datetime import datetime
import pandas as pd
import time
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'bf2a0fbecd7030220d754389dcbd5bd9'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ipnx:root.Account#20@ipNX@localhost/sitelist'
app.config["CLIENT_CSV"] = "/Users/user/Desktop/Grce/SiteList/site"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return user_login.query.get(int(user_id))

class user_login(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(12), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    timestamp = db.Column(db.DateTime(6), nullable=False)
    
    def __repr__(self):
        return f"User('{self.username}')"
    
class report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    date = db.Column(db.DateTime(6), nullable=False)
    device = db.Column(db.String(250), nullable=False)
    details = db.Column(db.String(250), nullable=False)
    comment = db.Column(db.String(250), nullable=False)
    
    def __repr__(self):
        return "id: {0} | name: {1} | date: {2} | device: {3}  | details: {4} | comment: {5} |".format(self.id, self.name, self.date, self.device, self.details, self.comment)

class closed(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    date = db.Column(db.DateTime(6), nullable=False)
    device = db.Column(db.String(250), nullable=False)
    details = db.Column(db.String(250), nullable=False)
    comment = db.Column(db.String(250), nullable=False)
    
    def __repr__(self):
        return "id: {0} | name: {1} | date: {2} | device: {3}  | details: {4} | comment: {5} |".format(self.id, self.name, self.date, self.device, self.details, self.comment)


@app.route("/")
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']
        usr = user_login.query.filter_by(username=username).first()
        if usr and bcrypt.check_password_hash(usr.password, password):
            login_user(usr)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check Username and Password')
            return redirect(url_for('login'))
    return render_template('index.html')

@app.route("/index")
def index():
    qry = report.query.all()
    return render_template('home.html', repo=qry)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['POST', 'GET'])
@login_required
def register():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        email = data['email']
        password = str(data['password'])
        passwordd = str(data['passwordd'])
        usr = user_login.query.filter_by(username=username).first()
        if usr:
            flash('Username already exists')
            return redirect(url_for('admintable'))
        if len(username) < 5 or len(username) >12:
            flash('Username should have more than 4 characters but less than 12')
            return redirect(url_for('admintable'))
        if len(password) < 5:
            flash('Passwords should have more than 4 characters')
            return redirect(url_for('admintable'))
        if password != passwordd:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('admintable'))
        else:
            hashed_psw = bcrypt.generate_password_hash(password).decode('utf-8')
            user = user_login(username=username, email=email, password=hashed_psw)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
        
@app.route('/contact', methods = ['GET', 'POST'])
def contact():
    flash("Comment Submitted")
    return redirect(url_for('login'))

@app.route('/update/add', methods=['POST', 'GET'])
def add_site():
    if request.method == 'POST':
        data = request.form
        name = data['name']
        device = data['device']
        details = data['details']
        comment = data['comment']
        date = datetime.now()
        repo = report(name=name, date=date, device=device, details=details, comment=comment)
        db.session.add(repo)
        db.session.commit()
        flash("Site Added Successfully")
        return redirect(url_for('index'))
        
@app.route("/update/<int:repo_id>", methods=['POST','GET'])
def update(repo_id):
    repo =report.query.get(repo_id)
    repor = closed(name=repo.name, date=repo.date, device=repo.device, details=repo.details, comment=repo.comment)
    db.session.add(repor)
    db.session.commit()
    db.session.delete(repo)
    db.session.commit()
    flash("Report closed")
    return redirect(url_for('index'))

@app.route('/closed_Report', methods=['POST','GET'])
def closed_Report():
    qry = closed.query.all()
    return render_template('home.html', rep=qry)

@app.route('/custom_Report', methods=['POST','GET'])
def custom_Report():
    qry = closed.query.all()
    return render_template('home.html', rep=qry)