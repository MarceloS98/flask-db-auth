from flask import Flask, render_template, redirect, request, url_for 
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'shupetsss'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class LoginForm(FlaskForm):
    email = EmailField('email')
    password = PasswordField('pass')
    submit = SubmitField('Logueate')

class RegisterForm(FlaskForm):
    name = StringField('name')
    email = EmailField('email')
    password = PasswordField('pass')
    submit = SubmitField('Registrate!')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(50), nullable = False)
    email = db.Column(db.String(80), nullable = False)
    password = db.Column(db.String(80), nullable = False)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    description = db.Column(db.String(200))
    is_completed = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            hashed_pass = check_password_hash(user.password, form.password.data)
            if hashed_pass:
                login_user(user)
                return redirect(url_for('todo'))

        return '<h1>Invalid username or passord</h1>'

    return render_template('login.html', form=form)

@app.route('/todo', methods=['POST', 'GET'])
@login_required
def todo():
    todos = Todo.query.filter_by(user_id=current_user.id)
    if request.method == 'POST':
        todo = Todo(
            description = request.form['description'],
            is_completed = False,
            user_id = current_user.id
        )
        db.session.add(todo)
        db.session.commit()
        return redirect(url_for('todo'))

    return render_template('todo.html', todos=todos)

@app.route('/delete/<id>')
@login_required
def delete(id):
    todo = Todo.query.filter_by(id=id).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('todo'))

@app.route('/update/<id>')
@login_required
def update(id):
    todo = Todo.query.filter_by(id=id).first()
    todo.is_completed = not todo.is_completed
    db.session.commit()
    return redirect(url_for('todo'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('register'))