import mysql.connector

def create_example_database():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="ton_mot_de_passe",
        database="ta_base"
    )
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email TEXT NOT NULL
        )
    ''')

    sample_users = [
        ('Alice Johnson', 'alice@example.com'),
        ('Bob Smith', 'bob.smith@example.com'),
        ('Carol White', 'carol.white@example.com'),
        ('David Brown', 'david.brown@example.com')
    ]

    cursor.execute('DELETE FROM users')  # Pour repartir de zéro
    cursor.executemany('INSERT INTO users (name, email) VALUES (%s, %s)', sample_users)
    conn.commit()
    conn.close()
    print("Base de données MySQL initialisée avec utilisateurs.")


def encrypt(data: str) -> str:
    return data[::-1]

def decrypt(data: str) -> str:
    return data[::-1]

def encrypt_existing_emails():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="ton_mot_de_passe",
        database="ta_base"
    )
    cursor = conn.cursor()

    cursor.execute("SELECT id, email FROM users")
    rows = cursor.fetchall()

    print(f"Chiffrement de {len(rows)} adresses email...")

    for user_id, email in rows:
        if email is None:
            continue
        encrypted_email = encrypt(email)
        cursor.execute("UPDATE users SET email = %s WHERE id = %s", (encrypted_email, user_id))
        print(f"User {user_id}: '{email}' -> '{encrypted_email}'")

    conn.commit()
    conn.close()
    print("Chiffrement terminé.")

def verify_encryption():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="ton_mot_de_passe",
        database="ta_base"
    )
    cursor = conn.cursor()

    cursor.execute("SELECT id, email FROM users")
    rows = cursor.fetchall()

    print("\nVérification des emails déchiffrés :")
    for user_id, encrypted_email in rows:
        if encrypted_email is None:
            continue
        decrypted_email = decrypt(encrypted_email)
        print(f"User {user_id}: Encrypted='{encrypted_email}' => Decrypted='{decrypted_email}'")

    conn.close()
