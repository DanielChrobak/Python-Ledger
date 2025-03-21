from functools import wraps
from flask import session, flash, redirect, url_for
from models import User, db

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def confirmation_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = db.session.get(User, session['user_id'])
        if not user.confirmed:
            flash('Please confirm your email to access this page', 'warning')
            return redirect(url_for('auth.unconfirmed'))
        return f(*args, **kwargs)
    return decorated_function
