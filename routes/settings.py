from flask import Blueprint, render_template, request, flash, session, url_for, redirect
from werkzeug.security import check_password_hash, generate_password_hash
from models import User, db
from utils import login_required, confirmation_required
from extensions import mail, serializer
from flask_mail import Message
from flask import current_app

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@confirmation_required
def settings():
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        
        if not check_password_hash(user.password, current_password):
            flash('Incorrect current password', 'danger')
            return render_template('settings.html', user=user)
        
        if 'new_username' in request.form:
            new_username = request.form['new_username']
            if User.query.filter(User.username == new_username, User.id != user.id).first():
                flash('Username already taken', 'danger')
            else:
                user.username = new_username
                db.session.commit()
                flash('Username updated successfully!', 'success')
        
        elif 'new_email' in request.form:
            new_email = request.form['new_email']
            if User.query.filter(User.email == new_email, User.id != user.id).first():
                flash('Email already registered', 'danger')
            else:
                try:
                    token = serializer.dumps(new_email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
                    confirm_url = url_for('auth.confirm_email', token=token, _external=True)
                    
                    msg = Message('Confirm Your New Email',
                          sender=('Ledger App', current_app.config['MAIL_USERNAME']),
                          recipients=[new_email])
                    msg.html = render_template('confirm_email.html', confirm_url=confirm_url)
                    mail.send(msg)
                    
                    user.email = new_email
                    user.confirmed = False
                    db.session.commit()
                    flash('Email updated. A confirmation link has been sent to your new email.', 'success')
                    return redirect(url_for('auth.unconfirmed'))
                except Exception as e:
                    db.session.rollback()
                    flash('Failed to send confirmation email. Please try again.', 'danger')
                    print(str(e))
        
        elif 'new_password' in request.form:
            new_password = request.form['new_password']
            if check_password_hash(user.password, new_password):
                flash('New password must be different', 'danger')
            else:
                user.password = generate_password_hash(new_password)
                db.session.commit()
                flash('Password updated successfully!', 'success')
    
    return render_template('settings.html', user=user)
