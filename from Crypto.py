
# Function to decrypt data with AES
def decrypt_data(encrypted_data, symmetric_key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

# Function to decrypt symmetric key with RSA
def decrypt_symmetric_key(encrypted_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(encrypted_key)

# Retrieve and decrypt user data
def retrieve_user(user_id, private_key):
    conn = sqlite3.connect('encrypted_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT email, encrypted_key FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        encrypted_email, encrypted_key = row
        symmetric_key = decrypt_symmetric_key(encrypted_key, private_key)
        decrypted_email = decrypt_data(encrypted_email, symmetric_key)
        return decrypted_email
    return None

# Main execution for retrieval
if __name__ == "__main__":
    # Assuming the private key is available
    decrypted_email = retrieve_user(1, private_key)  # Retrieve user with ID 1
    print(f"Decrypted Email for User ID 1: {decrypted_email}")

    decrypted_email = retrieve_user(2, private_key)  # Retrieve user with ID 2
    print(f"Decrypted Email for User ID 2: {decrypted_email}")
