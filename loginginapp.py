from asyncio import tasks
from pydoc import plain
from flask import Flask, render_template, redirect, url_for, flash, get_flashed_messages, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required, current_user
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SECRET_KEY'] = '7dj58920dj75893djd23'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=40), unique=True, nullable=False)
    email_address = db.Column(db.String(length=60), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    admin_level = db.Column(db.Integer(), default =0)

    @property
    def password(self):
        return self.password
    
    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    owner = db.Column(db.Integer(), db.ForeignKey('user.id'))
    status = db.Column(db.Integer(), default=1)
    access_level = db.Column(db.Integer(), default='public')


    def __repr__(self):
        return '<Task %r>' % self.id

class RegisterForm(FlaskForm):

    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username exists.  Please choose another')
    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email exists. Please choose another')

    username = StringField(label='User Name:', validators=[Length(min=3, max=30), DataRequired()])
    email_address = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='Password:', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password:', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')

class LoginForm(FlaskForm):
    username = StringField(label='User Name:', validators=[DataRequired()])
    password = PasswordField(label='Passowrd:', validators=[DataRequired()])
    submit = SubmitField(label='Login')


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/work', methods=['POST', 'GET'])
@login_required
def work():
    if request.method == 'POST':
        the_owner = current_user.username
        task_content = request.form['content']
        new_task = Item(content=task_content, owner=the_owner)
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/work')
        except:
            return 'error'
    else:
        tasks = Item.query.filter(Item.owner == current_user.username)
        return render_template('work.html', tasks=tasks)

@app.route('/personal', methods=['POST', 'GET'])
@login_required
def personal():
    if request.method == 'POST':
        the_owner = current_user.username
        task_content = request.form['content']
        new_task = Item(content=task_content, owner=the_owner)
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/personal')
        except:
            return 'error'
    else:
        items = Item.query.all()
        task = Item.query.all()
        user = current_user.username
        return render_template('personal.html', items=items, task=task, user=user)

@app.route('/register', methods=['GET','POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data, email_address=form.email_address.data, password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        return redirect(url_for('work'))
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'The error was: {err_msg}', category='danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correction(attempted_password=form.password.data):
            login_user(attempted_user)
            flash(f'You are logged in, {attempted_user.username}', category='success')
            return redirect(url_for('work'))
        else:
            flash('Username or password is incorrect', category='danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout_page():
    logout_user()
    flash("You have logged out", category='info')
    return redirect(url_for("home"))

@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Item.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/work')
    except:
        return 'error deleting task'

@app.route('/complete/<int:id>')
def complete(id):
    task_to_complete = Item.query.get_or_404(id)
    task_to_complete.status = 0
    task_datechange = Item.query.get_or_404(id)
    task_datechange.date_created = datetime.utcnow()
    try:
        db.session.commit()
        return redirect('/work')
    except:
        return 'error completing task'

@app.route('/access_level/<int:id>')
def access_level(id):
    task_to_private = Item.query.get_or_404(id)
    task_to_private.access_level = 'private'
    try:
        db.session.commit()
        return redirect('/work')
    except:
        return 'error setting task'

@app.route('/access_level_public/<int:id>')
def access_level_public(id):
    task_to_private = Item.query.get_or_404(id)
    task_to_private.access_level = 'public'
    try:
        db.session.commit()
        return redirect('/work')
    except:
        return 'error setting task'

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    task = Item.query.get_or_404(id)
    if request.method == 'POST':
        task.content = request.form['content']
        try:
            db.session.commit()
            return redirect('/work')
        except:
            return 'update error'
    else:
        return render_template('update.html', task=task)


if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0')