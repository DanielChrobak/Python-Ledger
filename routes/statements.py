from flask import Blueprint, render_template, send_file, session
from models import User, Transaction
from utils import login_required, confirmation_required
from datetime import datetime
import io
import csv
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import hashlib
import calendar
from extensions import db

statements_bp = Blueprint('statements', __name__)

@statements_bp.route('/statements')
@login_required
@confirmation_required
def statements():
    user = db.session.get(User, session['user_id'])
    years = db.session.query(
        db.extract('year', Transaction.timestamp)
    ).filter(
        (Transaction.sender_id == user.id) |
        (Transaction.recipient_id == user.id)
    ).distinct().all()

    transactions_by_year = {}
    for year in years:
        year_num = int(year[0])
        months = db.session.query(
            db.extract('month', Transaction.timestamp)
        ).filter(
            ((Transaction.sender_id == user.id) |
            (Transaction.recipient_id == user.id)) &
            (db.extract('year', Transaction.timestamp) == year_num)
        ).distinct().all()
        transactions_by_year[year_num] = [int(m[0]) for m in months]

    return render_template('statements.html',
                           transactions_by_year=transactions_by_year,
                           current_year=datetime.now().year)

@statements_bp.route('/download_statement/<int:year>/<int:month>/<string:format>')
@login_required
def download_statement(year, month, format):
    user = db.session.get(User, session['user_id'])
    query = Transaction.query.filter(
        ((Transaction.sender_id == user.id) |
        (Transaction.recipient_id == user.id))
    )

    if month > 0:  # Monthly statement
        query = query.filter(
            (db.extract('year', Transaction.timestamp) == year) &
            (db.extract('month', Transaction.timestamp) == month)
        )
    else:  # Yearly statement
        query = query.filter(db.extract('year', Transaction.timestamp) == year)

    transactions = query.order_by(Transaction.timestamp.asc()).all()

    if format == 'csv':
        file_data = generate_statement_csv(transactions)
        mimetype = 'text/csv'
        filename = f"statement_{year}_{month:02d}.csv"
    elif format == 'pdf':
        file_data = generate_statement_pdf(transactions, year, month, user)
        mimetype = 'application/pdf'
        filename = f"statement_{year}_{month:02d}.pdf"
    else:
        return "Invalid format", 400

    file_hash = calculate_file_hash(file_data)
    response = send_file(
        io.BytesIO(file_data.encode()) if isinstance(file_data, str) else file_data,
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename
    )
    response.headers['X-File-Hash'] = file_hash
    response.headers['X-Hash-Algorithm'] = 'sha256'
    return response

def generate_statement_csv(transactions):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Type', 'Amount', 'Note'])
    for tx in transactions:
        writer.writerow([
            tx.timestamp.strftime("%Y-%m-%d %H:%M"),
            'Sent' if tx.sender_id == session['user_id'] else 'Received',
            f"${tx.amount:.2f}",
            tx.note or "No note"
        ])
    return output.getvalue()

def generate_statement_pdf(transactions, year, month, user):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )

    elements = []
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.gray
    )

    elements.append(Paragraph("Ledger App", title_style))
    elements.append(Paragraph(f"Statement for: {user.username}", header_style))
    period = f"{calendar.month_name[month]} {year}" if month > 0 else str(year)
    elements.append(Paragraph(f"Period: {period}", header_style))
    elements.append(Paragraph(f"Account ID: {user.id}", header_style))
    elements.append(Spacer(1, 20))

    table_data = [['Date', 'Type', 'Amount', 'Description']]
    for tx in transactions:
        date = tx.timestamp.strftime("%Y-%m-%d %H:%M")
        tx_type = 'Sent' if tx.sender_id == user.id else 'Received'
        amount = f"${tx.amount:.2f}"
        if tx_type == 'Sent':
            amount = f"-{amount}"
        note = tx.note or 'No note'
        table_data.append([date, tx_type, amount, note])

    table = Table(table_data, colWidths=[1.5*inch, inch, inch, 3*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f0')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (-1, 0), (-1, -1), 'LEFT'),
    ]))
    elements.append(table)

    elements.append(Spacer(1, 20))
    total_sent = sum(tx.amount for tx in transactions if tx.sender_id == user.id)
    total_received = sum(tx.amount for tx in transactions if tx.recipient_id == user.id)
    summary_data = [
        ['Total Sent:', f"${total_sent:.2f}"],
        ['Total Received:', f"${total_received:.2f}"],
        ['Net Change:', f"${(total_received - total_sent):.2f}"]
    ]
    summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (-1, -1), (-1, -1),
         colors.green if (total_received - total_sent) >= 0 else colors.red),
    ]))
    elements.append(summary_table)

    doc.build(elements)
    buffer.seek(0)
    return buffer

def calculate_file_hash(file_data):
    return hashlib.sha256(file_data.encode() if isinstance(file_data, str) else file_data.getvalue()).hexdigest()

@statements_bp.app_template_filter('month_name')
def month_name_filter(month_number):
    return calendar.month_name[month_number]
