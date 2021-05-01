from flask import Blueprint, render_template, request, flash, url_for, redirect
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
@auth.route('/signin', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True) # remember - user is logged in until user clear browsing history of their session
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password , try again!', category='error')
        else:
                flash('Email does not exists!', category='error')

    data = request.form
    print(data)
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@auth.route('/signout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/register', methods=['GET', 'POST'])
@auth.route('/signup', methods=['GET', 'POST'])
@auth.route('/sign-up', methods=['GET', 'POST'])
def register():
    if  request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already exists!", category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters', category='error')
        elif len(name) < 2:
            flash("Length of name must be greater than 1 character", category='error')
        elif password1 != password2:
            flash('Password and confirm password must be same', category='error')
        elif len(password1) < 8:
            flash('Password must be greater than 7 characters', category='error')
        else:
            new_user = User(email=email, name=name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash("Account successfully created!", category='success')
            return redirect(url_for('views.home'))

            # add user to database
    return render_template("sign_up.html", user=current_user)