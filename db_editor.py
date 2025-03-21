import sqlite3
import uuid
from werkzeug.security import generate_password_hash

DB_FILE = 'instance\ledger.db'

def connect_db():
    return sqlite3.connect(DB_FILE)

def view_users():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, balance FROM user")
    users = cursor.fetchall()
    conn.close()

    print("\nUser List:")
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Balance: ${user[2]:.2f}")

def edit_balance():
    user_id = input("Enter user ID: ")
    new_balance = float(input("Enter new balance: "))

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_balance, user_id))
    conn.commit()
    conn.close()

    print(f"Balance updated for user {user_id}")

def add_test_user():
    username = input("Enter username for test user: ")
    password = input("Enter password for test user: ")
    balance = float(input("Enter initial balance for test user: "))

    hashed_password = generate_password_hash(password)
    user_id = str(uuid.uuid4())

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO user (id, username, password, balance) VALUES (?, ?, ?, ?)",
                   (user_id, username, hashed_password, balance))
    conn.commit()
    conn.close()

    print(f"Test user added. ID: {user_id}")

def main_menu():
    while True:
        print("\nDatabase Editor")
        print("1. View Users")
        print("2. Edit Balance")
        print("3. Add Test User")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            view_users()
        elif choice == '2':
            edit_balance()
        elif choice == '3':
            add_test_user()
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
