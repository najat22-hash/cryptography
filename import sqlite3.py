import sqlite3

def create_example_database(db_path='test_database.db'):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL
        );
    ''')

    # Insert some sample data
    sample_users = [
        ('Alice Johnson', 'alice@example.com'),
        ('Bob Smith', 'bob.smith@example.com'),
        ('Carol White', 'carol.white@example.com'),
        ('David Brown', 'david.brown@example.com')
    ]

    # Clear existing data for clean setup
    cursor.execute('DELETE FROM users')
    cursor.executemany('INSERT INTO users (name, email) VALUES (?, ?)', sample_users)
    conn.commit()
    conn.close()
    print(f"Database '{db_path}' created with sample users.")


if __name__ == '__main__':
    create_example_database()

import sqlite3

# Placeholder encryption function - replace with your cryptosystem logic
def encrypt(data: str) -> str:
    # Example: reverse string as dummy encryption
    return data[::-1]

# Placeholder decryption function for verification
def decrypt(data: str) -> str:
    return data[::-1]

def encrypt_existing_emails(db_path: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Fetch current emails (plain text)
    cursor.execute("SELECT id, email FROM users")
    rows = cursor.fetchall()

    print(f"Encrypting {len(rows)} email addresses...")

    for user_id, email in rows:
        if email is None:
            continue

        encrypted_email = encrypt(email)

        # Update the email field with the encrypted value
        cursor.execute("UPDATE users SET email = ? WHERE id = ?", (encrypted_email, user_id))

        # Optional: print before and after for verification
        print(f"User ID {user_id}: '{email}' -> '{encrypted_email}'")

    conn.commit()
    conn.close()
    print("Encryption complete.")

def verify_encryption(db_path: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, email FROM users")
    rows = cursor.fetchall()

    print(f"\nVerifying decrypted emails:")

    for user_id, encrypted_email in rows:
        if encrypted_email is None:
            continue

        decrypted_email = decrypt(encrypted_email)
        print(f"User ID {user_id}: Encrypted='{encrypted_email}', Decrypted='{decrypted_email}'")

    conn.close()

if __name__ == "__main__":
    DATABASE_FILE = "test_database.db"

    encrypt_existing_emails(DATABASE_FILE)
    verify_encryption(DATABASE_FILE)
