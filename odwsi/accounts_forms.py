from flask_wtf import FlaskForm
from wtforms import ValidationError, StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Regexp, Email

from odwsi.passwords_forms import reg_val
from odwsi.tables import User

email_reg = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'


class RegisterForm(FlaskForm):
    username = StringField(validators={InputRequired(), Length(min=4, max=80), Regexp(regex=email_reg)}, render_kw={"placeholder": "Email"})
    password = PasswordField(validators={InputRequired(), Length(min=4, max=20), Regexp(regex=reg_val)}, render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one")


class LoginForm(FlaskForm):
    username = StringField(validators={InputRequired(), Length(min=4, max=80), Regexp(regex=reg_val)}, render_kw={"placeholder": "Email"})
    password = PasswordField(validators={InputRequired(), Length(min=4, max=20), Regexp(regex=reg_val)}, render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(validators={InputRequired(), Length(min=4, max=20), Regexp(regex=reg_val)}, render_kw={"placeholder": "Old Password"})
    new_password = PasswordField(validators={InputRequired(), Length(min=4, max=20), Regexp(regex=reg_val)}, render_kw={"placeholder": "New Password"})
    submit = SubmitField("Change Password")


class ResetPasswordEmailForm(FlaskForm):
    email = StringField(validators={InputRequired(), Length(min=4, max=80), Regexp(regex=email_reg)}, render_kw={"placeholder": "Email"})
    submit = SubmitField("Send email")


class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators={InputRequired(), Length(min=4, max=20), Regexp(regex=reg_val)}, render_kw={"placeholder": "New Password"})
    submit = SubmitField("Change Password")
