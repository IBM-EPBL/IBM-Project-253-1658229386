from flask import Flask, render_template, request, redirect, url_for, session
import pickle
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt



app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/', methods=['GET', 'POST'])
def login():
    if 'admin' in session:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session['admin'] = request.form['username'] 
                return redirect(url_for('home'))
    
    return render_template('login.html', form=form)


@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'admin' not in session:
        return redirect(url_for('login'))
    else: 
        return render_template('home.html')


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    else:
        Warning('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('register.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/predict', methods=['GET', 'POST'])
def index():
    if 'admin' not in session:
        return redirect(url_for('login'))
    else:
        return render_template('predict.html')


@app.route('/data_predict', methods=['POST'])
def predict():

    age = request.form['age']
    gender = request.form['gender']
    tb = request.form['tb']
    dbi = request.form['dbi']
    ap = request.form['ap']
    aa1 = request.form['aa1']
    aa2 = request.form['aa2']
    tp = request.form['tp']
    a = request.form['a']
    agr = request.form['agr']
    if gender == "Male":
        gender = 1
    else:
        gender = 0
    data = [[float(age),
            float(gender),
            float(tb),
            float(dbi),
            float(ap),
            float(aa1),
            float(aa2),
            float(tp),
            float(a),
            float(agr)]]

    model = pickle.load(open('KNN_10thaug.pkl', 'rb'))

    prediction = model.predict(data)
    if (prediction == 1):
        return render_template('noChance.html',
                               prediction='You don\'t have disease.')
    else:
        return render_template('chance.html',
                               prediction='You dead boy.')


if __name__ == '__main__':
    app.run(debug=True)
