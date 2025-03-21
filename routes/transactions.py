from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from extensions import db, socketio
from models import User, Transaction
from utils import login_required, confirmation_required

transactions_bp = Blueprint('transactions', __name__)

@transactions_bp.route('/transfer', methods=['GET', 'POST'])
@login_required
@confirmation_required
def transfer():
    if request.method == 'POST':
        recipient_id = request.form['recipient_id']
        note = request.form.get('note', '')
        
        if len(note) > 140:
            flash('Note exceeds 140 characters. Please shorten your note.', 'danger')
            return render_template('transfer.html')
        
        try:
            amount = float(request.form['amount'])
            if amount <= 0:
                raise ValueError("Amount must be positive")
        except ValueError:
            flash('Invalid amount. Please enter a positive number.', 'danger')
            return render_template('transfer.html')
        
        sender = db.session.get(User, session['user_id'])
        recipient = User.query.filter_by(id=recipient_id).first()
        
        if not recipient:
            flash('Recipient not found!', 'danger')
        elif sender.id == recipient.id:
            flash('You cannot transfer money to yourself!', 'danger')
        elif sender.balance < amount:
            flash('Insufficient funds!', 'danger')
        else:
            try:
                # Perform transfer
                sender.balance -= amount
                recipient.balance += amount
                
                new_transaction = Transaction(
                    sender_id=sender.id,
                    recipient_id=recipient.id,
                    amount=amount,
                    note=note
                )
                
                db.session.add(new_transaction)
                db.session.commit()
                
                # Send real-time balance updates
                socketio.emit('balance_update', 
                    {'balance': sender.balance}, 
                    room=str(sender.id),  # Ensure room ID is string
                    namespace='/')

                socketio.emit('balance_update', 
                    {'balance': recipient.balance}, 
                    room=str(recipient.id),
                    namespace='/')
                
                flash(f'Transfer of ${amount:.2f} to {recipient.username} completed! Note: {note}', 'success')
                return redirect(url_for('transactions.transactions'))
            
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred during the transfer: {str(e)}', 'danger')
        
    return render_template('transfer.html')

@transactions_bp.route('/transactions')
@login_required
@confirmation_required
def transactions():
    user = db.session.get(User, session['user_id'])
    user_transactions = Transaction.query.filter(
        (Transaction.sender_id == user.id) | 
        (Transaction.recipient_id == user.id)
    ).order_by(Transaction.timestamp.desc()).all()
    
    return render_template('transactions.html', 
                         transactions=user_transactions,
                         user=user)
