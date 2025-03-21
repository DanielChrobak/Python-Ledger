# Python Ledger App

A secure and user-friendly web application for managing financial transactions, account balances, and generating statements.

## Features

- **User Authentication**
  - Secure signup and login
  - Two-factor authentication (2FA) support
  - Password recovery

- **Account Management**
  - Real-time balance tracking
  - Secure money transfers between accounts
  - Transaction history with advanced filtering

- **Security Features**
  - Two-factor authentication (2FA)
  - Real-time WebSocket updates with authentication
  - File integrity verification for downloads

- **Statements and Reports**
  - Monthly and yearly statements
  - PDF and CSV export options
  - Downloadable transaction history

- **User Settings**
  - Profile management (username, email, password)
  - Two-factor authentication toggle
  - Account information display

## Getting Started

### Prerequisites

- Python 3.7+
- Flask
- A database system (SQLite, PostgreSQL, etc.)
- WebSocket support (Socket.IO)

### Installation

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/python-ledger-app.git
   cd python-ledger-app
   ```

2. Create and activate a virtual environment
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables (if needed)
   - Create a `.env` file in the project root
   - Add necessary configuration variables (database URL, secret key, etc.)

5. Initialize the database
   ```bash
   flask db upgrade
   ```

6. Start the application
   ```bash
   flask run
   ```

## Usage Guide

### Account Setup

1. **Sign Up**
   - Navigate to the Sign Up page
   - Enter your email, username, and password
   - Submit the form to create your account

2. **Login**
   - Use your username/email and password to log in
   - If 2FA is enabled, you'll be prompted to enter your verification code

### Making Transactions

1. **Transfer Funds**
   - Navigate to the Transfer page
   - Enter the recipient's UUID
   - Specify the amount to transfer
   - Add an optional note (up to 140 characters)
   - Submit the form to complete the transfer

2. **View Transactions**
   - Go to the Transactions page to see your transaction history
   - Use the filtering options to search by:
     - Transaction UUID
     - Date range
     - Transaction type (sent or received)
     - Amount range
     - Notes
     - Recipient

### Managing Statements

1. **View Statements**
   - Navigate to the Statements page
   - Browse through statements organized by year and month

2. **Download Statements**
   - Click the "Download" button next to any statement
   - Choose between PDF and CSV formats
   - Files are verified for integrity using SHA-256 hashing

### Account Settings

1. **Update Profile Information**
   - Go to the Settings page
   - Use the respective buttons to change your:
     - Username
     - Email
     - Password

2. **Enable/Disable 2FA**
   - Toggle the 2FA switch on the Settings page
   - Confirm with your password when prompted

## Security Features

### Two-Factor Authentication

The app supports two-factor authentication to add an extra layer of security to your account. When enabled, you'll need to provide a verification code in addition to your password during login.

### Real-time Balance Updates

The dashboard displays your current balance in real-time using WebSocket connections. Any changes to your balance (e.g., when you receive money) are immediately reflected without needing to refresh the page.

### File Integrity Verification

When downloading statements, the app performs integrity verification:

1. The server generates a SHA-256 hash of the file before sending it
2. After download, the client calculates its own hash of the received file
3. The hashes are compared to ensure the file wasn't tampered with during transfer

## Troubleshooting

- **Login Issues**: If you're having trouble logging in, check that your username/email and password are correct. If you've forgotten your password, use the "Forgot Password" link.

- **Transfer Problems**: Ensure the recipient UUID is correct and that you have sufficient funds for the transfer.

- **2FA Problems**: If you're unable to access your 2FA device, contact the administrator for assistance.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
