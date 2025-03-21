from flask import Blueprint, render_template, session
from utils import login_required, confirmation_required
from models import User
from extensions import db

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def home():
    """Main landing page route"""
    return render_template('home.html')

@home_bp.route('/dashboard')
@login_required
@confirmation_required
def dashboard():
    """Authenticated user dashboard"""
    user = db.session.get(User, session['user_id'])
    return render_template('dashboard.html', user=user)
