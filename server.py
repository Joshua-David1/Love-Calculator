from flask import Flask, render_template, redirect, url_for, request, session, g, jsonify
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, InputRequired, Regexp, ValidationError, Length
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from random import randint
from decouple import config
import psycopg2

random_percent = randint(1,100)

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = config('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = config('SQLALCHEMY_DATABASE_URI','sqlite:///users-data-collection.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'off'
db = SQLAlchemy(app)

class User(UserMixin,db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30), unique = True,  nullable = False)
	password = db.Column(db.String(25), nullable = False)

class Crush(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	to_username = db.Column(db.String(30), nullable = False)
	from_username = db.Column(db.String(30), nullable = False)
	crush_name = db.Column(db.String(30), nullable = False)

db.create_all()

def min_char_check(form, field):
	if len(field.data) < 6:
		raise ValidationError("Minimum 6 characters are required")

class User_check(object):
    def __init__(self, register = False):
        self.register = register
        self.login_message = "user unavailable"
        self.register_message = "user already exists"

    def __call__(self, form, field):
        if self.register:
            user = User.query.filter_by(username = field.data).first()
            if user:
                raise ValidationError(self.register_message)
        else:
            user = User.query.filter_by(username = field.data).first()
            if user == None:
                    raise ValidationError(self.login_message)

user_check = User_check


class Pass_check(object):
    def __init__(self):
        self.error_message = "Incorrect Password"

    def __call__(self, form, field):
        user = User.query.filter_by(username = form.username.data).first()
        if user is None or field.data != user.password:
            raise ValidationError('Password Incorrect')
                    
pass_check = Pass_check

class LoginForm(FlaskForm):
	username = StringField('username',render_kw ={"placeholder":'username','maxlength':25} , validators = [DataRequired("Username required"), user_check()])
	password = PasswordField('password', render_kw = {"placeholder" : "password",'maxlength':20}, validators=[DataRequired("Enter password"), min_char_check, pass_check()])

class RegisterForm(FlaskForm):
	username = StringField('username', render_kw = {'placeholder':'username', 'maxlength':25}, validators = [DataRequired("Username required"), min_char_check, user_check(register = True), Regexp("^[\w]*$", message="Only letter, numbers and underscore."),Regexp("^[a-z\_0-9]*$", message="Only small letters"), Regexp("^[a-z\_]+[a-z\_0-9]*$", message="Cannot begin with numbers") ])
	password = PasswordField('password', render_kw = {"placeholder" : "password", 'maxlength':20}, validators=[DataRequired("Enter password"), min_char_check])


class CrushForm(FlaskForm):
	person_name = StringField('person_name', render_kw={"placeholder":"Enter you name", "maxlength":20}, validators = [DataRequired(), Length(min=4, message="You name is too short!")])
	crush_name = StringField('crush_name', render_kw = {"placeholder":"You crush", 'maxlength':20}, validators = [DataRequired(), Length(min=4,message="Your crush's name is too short!")])


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=10)
    session.modified = True
    g.user = current_user

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/")
def start_page():
	return redirect(url_for('login_page'))

@app.route("/login", methods=["POST","GET"])
def login_page():
	form = LoginForm()
	if not current_user.is_authenticated:
		if form.validate_on_submit():
			username = form.username.data
			password = form.password.data
			user = User.query.filter_by(username = username).first()
			login_user(user)
			return redirect(url_for('home_page'))
		return render_template('signing_page.html', form=form, form_name="login", button_name="Sign-In",choice="Don't have an account?",redirect_link="register_page", redirect_text=" Signup")
	return redirect(url_for('home_page'))

@app.route("/register", methods=["POST","GET"])
def register_page():
	form = RegisterForm()
	if not current_user.is_authenticated:
		if form.validate_on_submit():
			username = form.username.data
			password = form.password.data
			user = User(username = username,password = password)
			db.session.add(user)
			db.session.commit()
			login_user(user)
			return redirect(url_for('home_page'))
		return render_template('signing_page.html',form = form, form_name="register", button_name="Sign-Up", choice="Already have an account?", redirect_link="login_page", redirect_text="SignIn")
	return redirect(url_for('home_page'))

@app.route("/user-homepage")
def home_page():
	if current_user.is_authenticated:
		id = current_user.id
		prank_url  = request.url_root+'crush/'+str(id)
		crush_list = Crush.query.filter_by(to_username = current_user.username).all()
		return render_template('user-home-page.html', prank_url= prank_url,crush_list=crush_list[::-1])
	return redirect(url_for('login_page'))

@app.route("/crush/<id>",methods=["POST","GET"])
def crush_details(id):
	form = CrushForm()
	if form.validate_on_submit():
		person_name = form.person_name.data
		crush_name = form.crush_name.data
		user = User.query.filter_by(id = id).first()
		crush = Crush(to_username=user.username, from_username=person_name, crush_name=crush_name)
		db.session.add(crush)
		db.session.commit()
		return redirect(url_for('prank_page',id = id))
	user = User.query.filter_by(id=id).first()
	print(user)
	if user != None:
		return render_template('crush-details-page.html', form=form,id=id,name=user.username, percent=random_percent)
	return redirect(url_for('login_page'))

@app.route('/pranked', methods=["POST","GET"])
def prank_page():
	id = request.args.get('id')
	if id !=None:
		user = User.query.filter_by(id = id).first()
		if user != None:
			name = user.username
			return render_template('prank-page.html', name=name)
	return redirect(url_for('login_page'))


@app.route("/logout",methods=["POST","GET"])
def logout_page():
	if current_user.is_authenticated:
		if request.method == "POST":
			logout_user()
	return redirect(url_for('login_page'))

@app.route("/available-users")
def user_list_page():
	users = User.query.all()
	users_list = [user.username for user in users]
	return jsonify({"Users":users_list})

if __name__ == "__main__":
	app.run(debug = True)