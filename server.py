from flask import Flask, render_template, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, InputRequired
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)


app.config['SECRET_KEY'] = "Therla"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users-data-collection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'off'
db = SQLAlchemy(app)

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30), unique = True,  nullable = False)
	password = db.Column(db.String(25), nullable = False)

class Crush(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	to_username = db.Column(db.String(30), nullable = False)
	from_username = db.Column(db.String(30), nullable = False)
	crush_name = db.Column(db.String(30), nullable = False)

db.create_all()

class LoginForm(FlaskForm):
	username = StringField('username',render_kw ={"placeholder":'username','maxlength':25} , validators = [DataRequired()])
	password = PasswordField('password', render_kw = {"placeholder" : "password",'maxlength':20})

class RegisterForm(FlaskForm):
	username = StringField('username', render_kw = {'placeholder':'username', 'maxlength':25}, validators = [DataRequired()])
	password = PasswordField('password', render_kw = {"placeholder" : "password", 'maxlength':20})


class CrushForm(FlaskForm):
	crush_name = StringField('crush_name', render_kw = {"placeholder":"You crush", 'maxlength':20}, validators = [DataRequired()])

@app.route("/")
def start_page():
	return redirect(url_for('login_page'))

@app.route("/login", methods=["POST","GET"])
def login_page():
	form = LoginForm()
	if request.method == "POST":
		return redirect(url_for('home_page'))
	return render_template('signing_page.html', form=form, form_name="login", button_name="Sign-In",choice="Don't have an account?",redirect_link="register_page", redirect_text=" Signup")

@app.route("/register", methods=["POST","GET"])
def register_page():
	form = RegisterForm()
	if request.method == "POST":
		return redirect(url_for('home_page'))
	return render_template('signing_page.html',form = form, form_name="register", button_name="Sign-Up", choice="Already have an account?", redirect_link="login_page", redirect_text="SignIn")


@app.route("/user-homepage")
def home_page():
	return render_template('user-home-page.html')

@app.route("/crush",methods=["POST","GET"])
def crush_details():
	form = CrushForm()
	if request.method == "POST":
		return redirect(url_for('prank_page'))
	return render_template('crush-details-page.html', form=form)

@app.route('/pranked', methods=["POST","GET"])
def prank_page():
	return render_template('prank-page.html')

if __name__ == "__main__":
	app.run(debug = True)