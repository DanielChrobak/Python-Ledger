import sqlite3
import uuid
import random
from datetime import datetime
from werkzeug.security import generate_password_hash

DB_FILE = 'instance/ledger.db'
TEST_RECIPIENT_USERNAME = 'transaction_generator_bot'

def connect_db():
    return sqlite3.connect(DB_FILE)

def create_test_recipient():
    conn = connect_db()
    cursor = conn.cursor()
    
    # Check if test recipient already exists
    cursor.execute("SELECT id FROM user WHERE username = ?", (TEST_RECIPIENT_USERNAME,))
    if cursor.fetchone():
        return
    
    # Create test recipient user
    user_id = str(uuid.uuid4())
    hashed_password = generate_password_hash(str(uuid.uuid4()))
    test_email = f"{TEST_RECIPIENT_USERNAME}@example.com"
    cursor.execute("INSERT INTO user (id, username, password, balance, email) VALUES (?, ?, ?, ?, ?)",
                   (user_id, TEST_RECIPIENT_USERNAME, hashed_password, 100000.0, test_email))
    conn.commit()
    conn.close()

def generate_transactions(target_uuid, num_transactions, start_year, end_year):
    conn = connect_db()
    cursor = conn.cursor()
    
    # Get test recipient UUID
    cursor.execute("SELECT id FROM user WHERE username = ?", (TEST_RECIPIENT_USERNAME,))
    recipient_uuid = cursor.fetchone()[0]
    
    for _ in range(num_transactions):
        # Generate a unique ID for the transaction
        transaction_id = str(uuid.uuid4())
        
        # Generate random date within range
        year = random.randint(start_year, end_year)
        month = random.randint(1, 12)
        day = random.randint(1, 28)  # Safe day for all months
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        
        timestamp = datetime(year, month, day, hour, minute, second).strftime('%Y-%m-%d %H:%M:%S')
        amount = round(random.uniform(10.0, 2000.0), 2)
        
        # Randomly decide if target is sender or recipient
        if random.choice([True, False]):
            sender_id = target_uuid
            recipient_id = recipient_uuid
        else:
            sender_id = recipient_uuid
            recipient_id = target_uuid
        
        # Insert transaction (note the escaped table name and added id field)
        cursor.execute("""
            INSERT INTO "transaction" 
            (id, sender_id, recipient_id, amount, timestamp, note)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            transaction_id,
            sender_id,
            recipient_id,
            amount,
            timestamp,
            random.choice(['Groceries', 'Utilities', 'Rent', 'Payment', 'Transfer', 'Service'])
        ))
    
    conn.commit()
    conn.close()

def main():
    create_test_recipient()
    
    target_uuid = input("Enter target user UUID: ").strip()
    num_transactions = int(input("Number of transactions to generate: "))
    start_year = int(input("Start year (e.g., 2020): "))
    end_year = int(input("End year (e.g., 2023): "))
    
    generate_transactions(target_uuid, num_transactions, start_year, end_year)
    print(f"Successfully generated {num_transactions} transactions between {start_year}-{end_year}")

if __name__ == "__main__":
    main()
