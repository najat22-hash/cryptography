import os
import base64
import time
import mysql.connector
from statistics import mean
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

# ========== Connexion MySQL ==========

def connect_mysql():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="cryptography"
    )

# ========== Initialisation des tables ==========

def init_tables():
    conn = connect_mysql()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS encryption_keys (
            id INT PRIMARY KEY AUTO_INCREMENT,
            aes_key TEXT NOT NULL
        )
    """)

    tables = {
        "users": [
            "CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), email TEXT)",
            [("Alice", "alice@example.com"), ("Bob", "bob@example.com")]
        ],
        "clients": [
            "CREATE TABLE IF NOT EXISTS clients (id INT AUTO_INCREMENT PRIMARY KEY, fullname VARCHAR(100), contact_email TEXT)",
            [("Sophie Martin", "sophie.martin@client.com"), ("Marc Duval", "marc@duval.org")]
        ],
        "employees": [
            "CREATE TABLE IF NOT EXISTS employees (id INT AUTO_INCREMENT PRIMARY KEY, emp_name VARCHAR(100), emp_email TEXT)",
            [("Sarah Lopez", "sarah@company.com"), ("Nicolas Jean", "nicolas.jean@company.com")]
        ]
    }

    for table, (create_sql, rows) in tables.items():
        cursor.execute(create_sql)
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        if cursor.fetchone()[0] == 0:
            placeholders = ",".join(["%s"] * len(rows[0]))
            insert_sql = f"INSERT INTO {table} VALUES (NULL, {placeholders})"
            cursor.executemany(insert_sql, rows)
            print(f"✅ Table `{table}` initialisée avec {len(rows)} lignes.")

    conn.commit()
    conn.close()

# ========== Gestion de la clé AES persistante ==========

def generate_and_store_key():
    t0 = time.time()
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_private = ec.generate_private_key(ec.SECP256R1())
    peer_public = peer_private.public_key()
    shared_secret = private_key.exchange(ec.ECDH(), peer_public)
    derived_key = HKDF(hashes.SHA256(), 32, None, b'handshake').derive(shared_secret)
    encoded_key = base64.b64encode(derived_key).decode()

    conn = connect_mysql()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM encryption_keys")
    cursor.execute("INSERT INTO encryption_keys (aes_key) VALUES (%s)", (encoded_key,))
    conn.commit()
    conn.close()
    print(f"🔐 Clé AES générée en {time.time() - t0:.4f}s et stockée.")

def load_key():
    conn = connect_mysql()
    cursor = conn.cursor()
    cursor.execute("SELECT aes_key FROM encryption_keys LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    if row:
        return base64.b64decode(row[0])
    else:
        print("❌ Aucune clé trouvée. Génération en cours...")
        generate_and_store_key()
        return load_key()

# ========== Chiffrement AES + Base64 ==========

def encrypt_data(data: bytes, key: bytes) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return base64.b64encode(iv + ct).decode()

def decrypt_data(encoded_data: str, key: bytes) -> str:
    raw = base64.b64decode(encoded_data.encode())
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decrypted_padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(decrypted_padded) + unpadder.finalize()).decode()

# ========== Chiffrement/Déchiffrement de colonnes ==========

def encrypt_column(table, column, key):
    conn = connect_mysql()
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, {column} FROM {table}")
    rows = cursor.fetchall()

    times = []
    for row_id, value in rows:
        if value is None:
            continue
        try:
            base64.b64decode(value.encode())
            continue  # déjà chiffré
        except:
            pass
        t0 = time.time()
        encrypted = encrypt_data(value.encode(), key)
        times.append(time.time() - t0)
        cursor.execute(f"UPDATE {table} SET {column} = %s WHERE id = %s", (encrypted, row_id))

    conn.commit()
    conn.close()
    print(f"🔒 Colonne `{column}` chiffrée dans `{table}` en {sum(times):.4f}s ({mean(times):.4f}s/ligne)")

def decrypt_column(table, column, key):
    import base64
    conn = connect_mysql()
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, {column} FROM {table}")
    rows = cursor.fetchall()

    print(f"\n🔓 Déchiffrement de `{table}`.{column}...")
    times = []
    for row_id, encrypted_val in rows:
        if not encrypted_val:
            continue
        try:
            base64.b64decode(encrypted_val.encode("utf-8"))
            t0 = time.time()
            decrypted = decrypt_data(encrypted_val, key)
            times.append(time.time() - t0)
            cursor.execute(f"UPDATE {table} SET {column} = %s WHERE id = %s", (decrypted, row_id))
            print(f"[{row_id}] ✅ {decrypted}")
        except Exception as e:
            print(f"[{row_id}] ❌ Erreur: {e}")

    conn.commit()
    conn.close()
    if times:
        print(f"✅ Déchiffré {len(times)} lignes en {sum(times):.4f}s ({mean(times):.4f}s/ligne)")

# ========== Stéganographie ==========

def hide_secret_in_image(secret_bytes, filename="cle_cachee.png"):
    secret_bin = ''.join(format(b, '08b') for b in secret_bytes)
    image = Image.new("RGBA", (100, 100), "white")
    pixels = list(image.getdata())
    idx = 0
    for i in range(len(pixels)):
        pixel = list(pixels[i])
        for n in range(4):
            if idx < len(secret_bin):
                pixel[n] = pixel[n] & ~1 | int(secret_bin[idx])
                idx += 1
        pixels[i] = tuple(pixel)
    image.putdata(pixels)
    image.save(filename)
    print(f"🖼️ Clé cachée dans l'image : {filename}")

# ========== Interface ==========

def interactive_console():
    key = load_key()

    while True:
        print("\n🎯 Que souhaitez-vous faire ?")
        print("1. Chiffrer un texte libre")
        print("2. Chiffrer une colonne d'une table")
        print("3. Déchiffrer une colonne d'une table")
        print("4. Cacher la clé dans une image")
        print("5. Quitter")

        choix = input("Votre choix : ")

        if choix == "1":
            texte = input("Texte à chiffrer : ")
            t0 = time.time()
            encrypted = encrypt_data(texte.encode(), key)
            enc_time = time.time() - t0

            t1 = time.time()
            decrypted = decrypt_data(encrypted, key)
            dec_time = time.time() - t1

            print(f"🔐 Chiffré : {encrypted}")
            print(f"🔓 Déchiffré : {decrypted}")
            print(f"⏱ Temps chiffrement: {enc_time:.4f}s, déchiffrement: {dec_time:.4f}s")

        elif choix == "2":
            table = input("Nom de la table : ")
            column = input("Nom de la colonne : ")
            encrypt_column(table, column, key)

        elif choix == "3":
            table = input("Nom de la table : ")
            column = input("Nom de la colonne : ")
            decrypt_column(table, column, key)

        elif choix == "4":
            hide_secret_in_image(key)

        elif choix == "5":
            print("👋 Fin du programme.")
            break

        else:
            print("❌ Option invalide.")

# ========== Main ==========

if __name__ == "__main__":
    init_tables()
    if not load_key():
        generate_and_store_key()
    interactive_console()