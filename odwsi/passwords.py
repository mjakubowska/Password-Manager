import uuid

from flask import render_template, redirect, url_for
from flask_login import login_required, current_user
from sqlalchemy import null

from odwsi import app, db, bcrypt
from odwsi.AESCipher import AESCipher
from odwsi.passwords_forms import AddPasswordForm, SharePasswordForm, ShowPasswordsPswdForm
from odwsi.tables import Passwords, User


def get_master_id(masters):
    last_master = masters[-1]
    return last_master.id + 1


class Master:
    def __init__(self, pswd_id, web_password, user_id, master_password):
        self.id = uuid.uuid4().bytes
        self.pswd_id = pswd_id
        self.web_password = web_password
        self.user_id = user_id
        self.master_password = master_password


global masters
masters = []


@app.route('/addPassword', methods={'GET', 'POST'})
@login_required
def add_password():
    form = AddPasswordForm()
    if form.validate_on_submit():
        user = current_user
        if bcrypt.check_password_hash(user.password, form.acc_password.data):
            aes = AESCipher(form.acc_password.data)
            encrypted_password = aes.encrypt(form.password.data)
            pass_id = get_pswd_id(user.id)
            new_row = Passwords(user_id=user.id, password_id=pass_id, website=form.website.data,
                                username=form.username.data, password=encrypted_password)
            db.session.add(new_row)
            db.session.commit()
            return redirect(url_for('add_password'))
    return render_template('addPassword.html', form=form)


@app.route('/sharePassword', methods={'GET', 'POST'})
@login_required
def share_password():
    user = current_user
    form = SharePasswordForm()
    form.website_select(current_user.id)
    if form.validate_on_submit():
        if bcrypt.check_password_hash(user.password, form.acc_password.data):
            aes_owner = AESCipher(form.acc_password.data)
            aes_share = AESCipher(form.master_password.data)
            pswd_row = Passwords.query.filter_by(password_id=get_website_id(form.website.data), user_id=current_user.id).scalar()
            user_id = db.session.query(User.id).filter(User.username == form.username.data).scalar()
            master_password = form.master_password.data
            web_password = aes_share.encrypt(aes_owner.decrypt(pswd_row.password))
            share = Master(pswd_row.id, web_password, user_id, master_password)
            masters.append(share)
            new_row = Passwords(password_id=get_pswd_id(user_id), user_id=user_id, website=pswd_row.website,
                                username=pswd_row.username, password=web_password, master_id=share.id)
            db.session.add(new_row)
            db.session.commit()
            msg = f'shared password for {form.website.data} to {form.username.data}'
    return render_template('sharePassword.html', form=form)


def get_website_id(s):
    list_string = s.partition('.')
    return int(list_string[0])


def get_pswd_id(user_id):
    last = db.session.query(Passwords.password_id).filter(Passwords.user_id == user_id) \
        .order_by(Passwords.password_id.desc()).first()
    if last is None:
        return 1
    else:
        return last[0] + 1


@app.route('/passwordTable', methods={'GET', 'POST'})
@login_required
def password_table():
    form = ShowPasswordsPswdForm()
    if form.validate_on_submit():
        user = current_user
        if bcrypt.check_password_hash(user.password, form.acc_password.data):
            rows = Passwords.query.filter_by(user_id=current_user.id).all()
            aes = AESCipher(form.acc_password.data)
            to_remove = []
            for i in range(len(rows)):
                print(rows[i].master_id)
                if rows[i].master_id is not None:
                    share = [x for x in masters if x.id == rows[i].master_id]
                    if len(share) == 0:
                        Passwords.query.filter_by(id=rows[i].id).delete()
                        to_remove.append(i)
                    else:
                        aes_share = AESCipher(share[0].master_password)
                        rows[i].password = aes_share.decrypt(rows[i].password)
                        row = Passwords.query.filter_by(id=rows[i].id)
                        setattr(row, 'password', aes.encrypt(rows[i].password))
                        setattr(row, 'master_id', null)
                        db.session.commit()
                        masters.remove(share[0])
                else:
                    rows[i].password = aes.decrypt(rows[i].password)
            rows = [rows[j] for j in range(len(rows)) if j not in to_remove]
            return render_template('passwordTable.html', form=form, rows=rows, ok=True)
    return render_template('passwordTable.html', form=form)
