import math

from bcrypt import gensalt
from flask import render_template, redirect, url_for, flash
from flask_login import login_user, LoginManager, login_required, logout_user, current_user
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer

from odwsi import app, db, bcrypt, mail
from odwsi.accounts_forms import LoginForm, ChangePasswordForm, RegisterForm, ResetPasswordForm, ResetPasswordEmailForm
from odwsi.tables import User

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def hello_world():  # put application's code here
    return render_template('index.html')


@app.route('/login', methods={'GET', 'POST'})
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/logout', methods={'GET', 'POST'})
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods={'GET', 'POST'})
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/changePassword', methods={'GET', 'POST'})
@login_required
def changePassword():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = current_user
        if user:
            if bcrypt.check_password_hash(user.password, form.old_password.data):
                hashed_new_password = bcrypt.generate_password_hash(form.new_password.data)
                user.password = hashed_new_password
                db.session.commit()
                return redirect(url_for('dashboard'))
    return render_template('changePassword.html', form=form)


def get_pepper():
    return "BP9kouP44KMjoz6stQAAwue.KnkHo6nqq69sz7qT3ITJlw.BA2THm"

def count_entropy(encrypted):
    prob = [float(encrypted.count(c)) / len(encrypted) for c in dict.fromkeys(list(encrypted)) ]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


@app.route('/register', methods={'GET', 'POST'})
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data, 15)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/resetPassword', methods={'GET', 'POST'})
def reset_email():
    form = ResetPasswordEmailForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.email.data).first_or_404()
        except:
            flash('Invalid email address!', 'error')
            return render_template('password_reset.html', form=form)

        send_password_reset_link(user.username)
        flash('Please check your email for a password reset link.', 'success')

    return render_template('password_reset.html', form=form)


def send_password_reset_link(user_email):
    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    password_reset_url = url_for(
        'token_reset',
        token=password_reset_serializer.dumps(user_email, salt='3d6f45a5fc12445dbac2f59c3b6c7cb1'),
        _external=True)

    html = render_template(
        'email_reset.html',
        password_reset_url=password_reset_url)

    msg = Message(
        'Hello',
        sender=app.config['MAIL_USERNAME'],
        recipients=[user_email]
    )
    msg.html = html
    mail.send(msg)


@app.route('/reset/<token>', methods=["GET", "POST"])
def token_reset(token):
    try:
        password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = password_reset_serializer.loads(token, salt='3d6f45a5fc12445dbac2f59c3b6c7cb1', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=email).first_or_404()
        except:
            flash('Invalid email address!', 'error')
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(form.password.data, 15)
        setattr(user, 'password', hashed_password)
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token_pass.html',token=token, form=form)

