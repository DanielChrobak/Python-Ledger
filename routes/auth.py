from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from utils import login_required
import uuid
from models import User, db
from extensions import mail, serializer, socketio
from flask_mail import Message
from flask import current_app
from flask_socketio import join_room, emit
import pyotp
import qrcode
import io

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    # Check if user is already logged in
    if 'user_id' in session:
        return redirect(url_for('home.dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(email=email).first():
            flash('Email address already registered', 'danger')
            return redirect(url_for('auth.signup'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('auth.signup'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(
            id=str(uuid.uuid4()),
            username=username,
            password=hashed_password,
            email=email
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            token = serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
            confirm_url = url_for('auth.confirm_email', token=token, _external=True)
            
            msg = Message('Confirm Your Ledger App Account',
                  sender=('Ledger App', current_app.config['MAIL_USERNAME']),
                  recipients=[email])
            msg.html = render_template('confirm_email.html', confirm_url=confirm_url)
            mail.send(msg)
            
            flash('A confirmation link has been sent to your email', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
            print(str(e))
    
    return render_template('signup.html')

@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(
            token,
            salt=current_app.config['SECURITY_PASSWORD_SALT'],
            max_age=3600
        )
    except:
        flash('The confirmation link is invalid or has expired', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first()
    if user.confirmed:
        flash('Account already confirmed', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = db.func.current_timestamp()
        db.session.commit()
        flash('Email confirmation successful!', 'success')
    
    return redirect(url_for('home.dashboard'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return jsonify({'success': True, 'redirect_url': url_for('home.dashboard')}) if request.method == 'POST' else redirect(url_for('home.dashboard'))

    if request.method == 'GET':
        return render_template('login.html')

    # Handle POST request (login attempt)
    username_or_email = request.form['username']
    password = request.form['password']

    user = User.query.filter((User.username == username_or_email) | 
                             (User.email == username_or_email)).first()

    if user and check_password_hash(user.password, password):
        if not user.confirmed:
            return jsonify({'success': False, 'error': 'Please confirm your email before logging in.'})

        if user.two_factor_enabled:
            session['pending_2fa_user'] = user.id
            return jsonify({'success': True, 'requires_2fa': True})

        session['user_id'] = user.id
        return jsonify({'success': True, 'redirect_url': url_for('home.dashboard')})

    return jsonify({'success': False, 'error': 'Invalid username/email or password'})

@auth_bp.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home.home'))

@auth_bp.route('/unconfirmed')
def unconfirmed():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    user = db.session.get(User, session['user_id'])
    if user.confirmed:
        return redirect(url_for('home.dashboard'))
    return render_template('unconfirmed.html')

@auth_bp.route('/resend_confirmation')
def resend_confirmation():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    user = db.session.get(User, session['user_id'])
    if user.confirmed:
        flash('Your account is already confirmed.', 'info')
        return redirect(url_for('home.dashboard'))
    
    token = serializer.dumps(user.email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
    confirm_url = url_for('auth.confirm_email', token=token, _external=True)
    
    msg = Message('Confirm Your Ledger App Account',
                  sender=('Ledger App', current_app.config['MAIL_USERNAME']),
                  recipients=[user.email])
    msg.html = render_template('confirm_email.html', confirm_url=confirm_url)
    mail.send(msg)
    
    flash('A new confirmation link has been sent to your email', 'success')
    return redirect(url_for('auth.unconfirmed'))

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender=('Ledger App', current_app.config['MAIL_USERNAME']),
                          recipients=[email])
            msg.html = render_template('reset_email.html', reset_url=reset_url)
            mail.send(msg)
        flash('If an account exists with that email, a reset link has been sent', 'info')
        return redirect(url_for('auth.login'))
    return render_template('forgot_password.html')

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Invalid or expired reset link', 'danger')
            return redirect(url_for('auth.forgot_password'))
        if request.method == 'POST':
            new_password = request.form['password']
            if check_password_hash(user.password, new_password):
                flash('New password must be different from the current password', 'danger')
                return render_template('reset_password.html')
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('auth.login'))
        return render_template('reset_password.html')
    except:
        flash('Invalid or expired reset link', 'danger')
        return redirect(url_for('auth.forgot_password'))

@auth_bp.route('/socket-auth')
@login_required
def socket_auth():
    return jsonify({'token': session['user_id']})

@socketio.on('authenticate')
def handle_authentication(data):
    user_id = data.get('token')
    if user_id and user_id == session.get('user_id'):
        join_room(str(user_id))
        emit('auth_success', {'status': 'authenticated'})
        print(f"User {user_id} authenticated via Socket.IO")

@auth_bp.route('/enable_2fa', methods=['POST'])
@login_required
def enable_2fa():
    data = request.get_json()
    password = data.get('password', '')
    user = db.session.get(User, session['user_id'])
    
    if not check_password_hash(user.password, password):
        return jsonify({'success': False, 'error': "Incorrect password."}), 400

    if user.two_factor_enabled:
        return jsonify({"success": False, "message": "2FA is already enabled."}), 400

    # Generate a new secret key for 2FA
    secret = pyotp.random_base32()
    user.two_factor_secret = secret
    user.two_factor_enabled = True
    db.session.commit()

    # Generate OTP URI
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Ledger App")

    # Generate QR Code
    qr = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)

    # Send email with QR code embedded
    msg = Message("Ledger App - Two-Factor Authentication Setup",
                  sender=("Ledger App", current_app.config['MAIL_USERNAME']),
                  recipients=[user.email])
    msg.html = render_template('2fa_email.html', otp_uri=otp_uri, secret=secret)
    msg.attach("2fa_qr.png", "image/png", img_io.getvalue(),
               headers={"Content-ID": "<qr_code>"})
    mail.send(msg)

    return jsonify({"success": True, "message": "2FA has been enabled. Please check your email for setup instructions."})

@auth_bp.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    data = request.get_json()
    password = data.get('password', '')
    user = db.session.get(User, session['user_id'])
    
    if not check_password_hash(user.password, password):
        return jsonify({'success': False, 'error': "Incorrect password."}), 400

    if not user.two_factor_enabled:
        return jsonify({'success': False, 'error': "2FA is already disabled."})
    
    # Disable 2FA for the user
    user.two_factor_enabled = False
    user.two_factor_secret = None
    db.session.commit()
    
    # Send an email notification to the user using a template that extends email_template.html
    msg = Message("Ledger App - Two-Factor Authentication Disabled",
                  sender=("Ledger App", current_app.config['MAIL_USERNAME']),
                  recipients=[user.email])
    msg.html = render_template('disable_2fa_email.html', username=user.username)
    mail.send(msg)
    
    return jsonify({'success': True, 'message': "2FA has been disabled and an email notification has been sent."})

@auth_bp.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    if 'pending_2fa_user' not in session:
        return jsonify({'success': False, 'error': 'Session expired. Please log in again.'})

    user = db.session.get(User, session['pending_2fa_user'])
    otp_token = request.form['otp']

    if not user or not user.two_factor_enabled:
        return jsonify({'success': False, 'error': 'Invalid session or 2FA not enabled.'})

    totp = pyotp.TOTP(user.two_factor_secret)
    if not totp.verify(otp_token):
        return jsonify({'success': False, 'error': 'Invalid 2FA code.'})

    session['user_id'] = user.id
    session.pop('pending_2fa_user', None)
    return jsonify({'success': True, 'redirect_url': url_for('home.dashboard')})