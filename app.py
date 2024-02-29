from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from datetime import datetime  
from flask import request

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'activity.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    activities = db.relationship('Activity', backref='user', lazy=True)

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_type = db.Column(db.String(50), nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = StringField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

class ActivityForm(FlaskForm):
    activity_type = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Activity Type"})
    duration = StringField(validators=[InputRequired()], render_kw={"placeholder": "Duration (minutes)"})
    submit = SubmitField("Add Activity")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.cli.command("create-db")
def create_db():
    db.create_all()
    print("Database tables created.")

@app.route('/')
def index():
    user_activity_counts = db.session.query(User, func.count(Activity.id)).outerjoin(Activity).group_by(User.id).order_by(func.count(Activity.id).desc()).all()
    return render_template('index.html', user_activity_counts=user_activity_counts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Cê errou a senha ou o usuário, amigão.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = ActivityForm()

    if form.validate_on_submit():
        new_activity = Activity(
            activity_type=form.activity_type.data,
            duration=form.duration.data,
            user_id=current_user.id
        )
        db.session.add(new_activity)
        db.session.commit()
        flash('Atividade adicionada com sucesso! Forçaaaaaaa Frango!')

    activities = Activity.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', name=current_user.username, form=form, activities=activities)

@app.route('/edit_activity/<int:activity_id>', methods=['GET', 'POST'])
@login_required
def edit_activity(activity_id):
    activity = Activity.query.get_or_404(activity_id)
    if activity.user_id != current_user.id:
        flash('Não é permitido que você edite essa atividade.')
        return redirect(url_for('dashboard'))

    form = ActivityForm()
    if form.validate_on_submit():
        activity.activity_type = form.activity_type.data
        activity.duration = form.duration.data
        db.session.commit()
        flash('Editado com sucesso, só não vale roubar!')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.activity_type.data = activity.activity_type
        form.duration.data = activity.duration
    return render_template('edit_activity.html', form=form)

@app.route('/delete_activity/<int:activity_id>', methods=['POST'])
@login_required
def delete_activity(activity_id):
    activity = Activity.query.get_or_404(activity_id)
    if activity.user_id != current_user.id:
        flash('Não é permitido que você exclua essa atividade.')
        return redirect(url_for('dashboard'))

    db.session.delete(activity)
    db.session.commit()
    flash('Atividade excluída com sucesso!')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)