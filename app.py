from flask import flash, Flask, render_template, redirect, url_for, g
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import exc
import os
import re
import json


def createFolder(directory):
    # create windows file
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print('Error: Creating directory. ' + directory)


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    safe0 = db.Column(db.String(50))
    safe1 = db.Column(db.String(50))
    safe2 = db.Column(db.String(50))

current_path = os.getcwd()
user_folder = ""

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


def is_valid_email(form, field):
    if (re.fullmatch("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$)", field.data) != None) == False:
        raise ValidationError("This is not an valid email address")

def exist_email(form, field):
    if isinstance(form, RegisterForm):
        if User.query.filter_by(email=field.data).first() != None:
            raise ValidationError("This email was registered already")
    elif isinstance(form, SafequestionanswerForm):
        if User.query.filter_by(email=field.data).first() == None:
            raise ValidationError("This email is not currently registered in the system")

def get_id_by_email(form, field):
    if User.query.filter_by(email=field.data).first() == None:
        raise ValidationError("This email is not register in the system")

def exist_username(form, field):
    if User.query.filter_by(username=field.data).first() != None:
        raise ValidationError("This username was registered already")

def verify_password(form, field):
    if field.data == form.password.data:
        pass
    else:
        raise ValidationError("The password is not equal to each other")

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50), exist_email, is_valid_email])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15), exist_username])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    repassword = PasswordField('re_password', validators=[InputRequired(), Length(min=8, max=80), verify_password])

class SafequestionForm(FlaskForm):
    #email = StringField('Please enter the email you used to register', validators=[InputRequired(), Length(max=50), exist_email])
    favorite_anime = StringField('You favorite anime show', validators=[InputRequired(), Length( max=80)])
    favorite_animecharacter = StringField('You favorite anime character', validators=[InputRequired(), Length(max=80)])
    favorite_country = StringField("The country you wish to travel in the future", validators=[InputRequired(), Length(max=80)])

class SafequestionanswerForm(FlaskForm):
    email = StringField('Please enter the email you used to register', validators=[InputRequired(), Length(max=50), exist_email])
    favorite_anime = StringField('You favorite anime show', validators=[InputRequired(), Length( max=80)])
    favorite_animecharacter = StringField('You favorite anime character', validators=[InputRequired(), Length(max=80)])
    favorite_country = StringField("The country you wish to travel in the future", validators=[InputRequired(), Length(max=80)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)

                if os.path.exists(os.path.join(current_path, user.id, "safequestion.json")):
                    flash("There safe question for the account is not set, please go and setup your safety question in case you forget your password")
                    return redirect(url_for('safequestion'))
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, safe0="", safe1="", safe2="")
        try:
            global user_folder
            db.session.add(new_user)
            db.session.commit()
            # use id for each user
            user_folder = os.path.join(current_path, "user_data", str(new_user.id))
            #print(user_folder)
            createFolder(user_folder)
            Flask.g = new_user.id

            return redirect(url_for('safequestion'))
        except exc.IntegrityError:

            db.session.rollback()
            return '<h1>Error</h1>'


        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)


@app.route('/safequestion', methods=['GET', 'POST'])
def safequestion():
    form = SafequestionForm()
    form.hidden_tag(""""<p class="help-block">This username was registered already</p>""")
    print("here")
    if form.validate_on_submit():
        global user_folder
        # note: the answer is not case sensitive, automatically will convert to lower case
        """
        hash_password1 = generate_password_hash(str(form.favorite_anime.data).lower())

        hash_password2 = generate_password_hash(str(form.favorite_animecharacter.data).lower())
        hash_password3 = generate_password_hash(str(form.favorite_country.data).lower())
        """
        # will use the ord plus 35 place

        hash_password1 = [ord(x) + 35 for x in str(form.favorite_anime.data).lower()]
        hash_password2 = [ord(x) + 35 for x in str(form.favorite_animecharacter.data).lower()]
        hash_password3 = [ord(x) + 35 for x in str(form.favorite_country.data).lower()]

        inital_value = {}

        for x in ['action', 'adventure', 'fantasy', 'science fiction', 'drama', 'romance', 'erotica', 'comedy', 'supernatural',
         'horror', 'mystery', 'psychological', 'thriller', 'slice of life', 'tournament', 'magic']:
            inital_value[x] = 0.1

        # give the key 0,1,2 for easy recall later when check

        answer = {"0": hash_password1, "1": hash_password2, "2":hash_password3}
        with open(os.path.join(user_folder, "safequestion.json"), "w") as file:
            file.write(json.dumps(answer))

        with open(os.path.join(user_folder, "info.json"), "w") as file:
            file.write(json.dumps(inital_value))

        return redirect(url_for('verifysafequestion'))
    else:
        return render_template('safequestion.html', form=form)

@app.route('/forgetpassword', methods=['GET', 'POST'])
def verifysafequestion():
    form = SafequestionanswerForm()
    if form.validate_on_submit():

        user_id = User.query.filter_by(email=form.email.data).first().id
        current_user_path = os.path.join(current_path, "user_data", str(user_id))
        if os.path.exists(os.path.join(current_user_path, "safequestion.json")):
            with open(os.path.join(current_user_path, "safequestion.json"), "r") as file:
                answer = json.loads(file.read())
            user_input = [form.favorite_anime.data, form.favorite_animecharacter.data, form.favorite_country.data]
            total_correct = 0


            # check the number of correct answer, all in lower letter



            for i in range(len(user_input)):
                print(answer[str(i)], user_input[i].lower())
                if "".join([ chr(int(x)-35) for x in answer[str(i)] ]) == user_input[i].lower():
                    total_correct += 1

            if total_correct >= 2:
                return """<h3>Correct input</h3>"""
            else:
                flash("You must have more than two correct answer")
                return redirect(url_for('verifysafequestion'))
        else:
            form.email.errors.append("The email was not registered with safety question at first")
            return render_template('forgetpassword.html', form=form)
    else:
        return render_template('forgetpassword.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':


    app.run(debug=True)
