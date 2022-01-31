from flask_login import UserMixin

from odwsi import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    master_id = db.Column(db.BLOB(16), nullable=True)
