import os
import uuid

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, template_folder='static/templates')
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"] = uuid.uuid4().hex
db = SQLAlchemy(app)
mail = Mail(app)
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.environ['EMAIL_USER']
app.config['MAIL_PASSWORD'] = os.environ['EMAIL_PASSWORD']
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


bcrypt = Bcrypt(app)
import odwsi.accounts, odwsi.passwords