from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, Regexp
from odwsi.tables import Passwords

reg_val = r'(^[a-zA-Z0-9\!\$\%\&\*\^\~\@\#\(\)_\-\\\/\.]*)$'


class AddPasswordForm(FlaskForm):
    website = StringField(validators={InputRequired(), Length(min=4, max=20),
                                      Regexp(regex=reg_val)}, render_kw={"placeholder": "Website"})
    username = StringField(validators={InputRequired(), Length(min=4, max=20),
                                       Regexp(regex=reg_val)}, render_kw={"placeholder": "Username"})
    password = PasswordField(validators={InputRequired(), Length(min=4, max=20),
                                         Regexp(regex=reg_val)}, render_kw={"placeholder": "Password"})
    acc_password = PasswordField(validators={InputRequired(), Length(min=4, max=20),
                                             Regexp(regex=reg_val)}, render_kw={"placeholder": "Account password"})
    submit = SubmitField("Add")


class ShowPasswordsPswdForm(FlaskForm):
    acc_password = PasswordField(validators={InputRequired(), Length(min=4, max=20), Regexp(regex=reg_val)}, render_kw={"placeholder": "Account password"})
    submit = SubmitField("Submit")


class SharePasswordForm(FlaskForm):
    website = SelectField(validators={InputRequired()})
    username = StringField(validators={InputRequired(), Length(min=4, max=20), Regexp(regex=reg_val)}, render_kw={"placeholder": "Email"})
    master_password = PasswordField(validators={InputRequired(), Length(min=4, max=20), Regexp(regex=reg_val)}, render_kw={"placeholder": "Password"})
    acc_password = PasswordField(validators={InputRequired(), Length(min=4, max=20), Regexp(regex=reg_val)}, render_kw={"placeholder": "Account password"})
    submit = SubmitField("Share")

    def website_select(self, user_id):
        self.website.choices = [f"{w.password_id}. {w.website}" for w in Passwords.query.filter_by(user_id=user_id).all()]


