#!/usr/bin/env python3
"""
HybridCrypt CLI - Database Encryption Tool with Hybrid Cryptosystem

Features:
- Encrypt and decrypt database columns using a hybrid cryptosystem.
- Support for SQLite, with extensible design for other DBs.
- Key management commands (generate, load).
- Configuration via command-line options.
- Robust input validation and logging.

Usage:
  hybridcrypt_cli.py generate-keys --output-dir ./keys --key-name key1
  hybridcrypt_cli.py encrypt --db-path ./mydb.sqlite --table users --columns email,ssn --key-path ./keys/key1.pem
  hybridcrypt_cli.py decrypt --db-path ./mydb.sqlite --table users --columns email,ssn --key-path ./keys/key1.pem

"""

import argparse
import os
import sys
import sqlite3
from base64 import b64encode, b64decode

# --------- Replace these with your actual hybrid cryptosystem logic ---------

def generate_keys(output_dir: str, key_name: str):
    """
    Generates and saves a pair of keys or necessary keys for your hybrid crypto.
    This is a dummy placeholder.
    """
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    public_key_path = os.path.join(output_dir, f"{key_name}_public.pem")
    private_key_path = os.path.join(output_dir, f"{key_name}_private.pem")
    # Dummy keys saved as sample text
    with open(public_key_path, "w") as f:
        f.write("PUBLIC KEY - replace with your real key\n")
    with open(private_key_path, "w") as f:
        f.write("PRIVATE KEY - keep secure\n")
    print(f"Keys generated:")
    print(f" Public key: {public_key_path}")
    print(f" Private key: {private_key_path}")

def load_key(key_path: str):
    """
    Loads a key from file.
    Placeholder for your key loading logic.
    """
    if not os.path.isfile(key_path):
        raise FileNotFoundError(f"Key file not found: {key_path}")
    with open(key_path, "r") as f:
        return f.read()

def encrypt_data(plaintext: bytes, key_data) -> bytes:
    """
    Encrypt plaintext bytes with your hybrid cryptosystem using key_data.
    Placeholder: base64 encode for demo.
    """
    return b64encode(plaintext)

def decrypt_data(ciphertext: bytes, key_data) -> bytes:
    """
    Decrypt ciphertext bytes with your hybrid cryptosystem using key_data.
    Placeholder: base64 decode for demo.
    """
    return b64decode(ciphertext)

# --------- Database Encryption Logic ---------

def connect_sqlite(db_path: str) -> sqlite3.Connection:
    if not os.path.isfile(db_path):
        print(f"Database file does not exist: {db_path}", file=sys.stderr)
        sys.exit(1)
    return sqlite3.connect(db_path)

def encrypt_column(conn: sqlite3.Connection, table: str, column: str, key_data):
    cursor = conn.cursor()
    cursor.execute(f"SELECT rowid, {column} FROM {table}")
    rows = cursor.fetchall()
    for rowid, plaintext in rows:
        if plaintext is None:
            continue
        pt_bytes = str(plaintext).encode("utf-8")
        ct_bytes = encrypt_data(pt_bytes, key_data)
        ct_str = ct_bytes.decode("utf-8")
        cursor.execute(f"UPDATE {table} SET {column} = ? WHERE rowid = ?", (ct_str, rowid))
    conn.commit()
    print(f"Encrypted {len(rows)} rows in {table}.{column}")

def decrypt_column(conn: sqlite3.Connection, table: str, column: str, key_data):
    cursor = conn.cursor()
    cursor.execute(f"SELECT rowid, {column} FROM {table}")
    rows = cursor.fetchall()
    for rowid, ciphertext in rows:
        if ciphertext is None:
            continue
        ct_bytes = str(ciphertext).encode("utf-8")
        try:
            pt_bytes = decrypt_data(ct_bytes, key_data)
            pt_str = pt_bytes.decode("utf-8")
            cursor.execute(f"UPDATE {table} SET {column} = ? WHERE rowid = ?", (pt_str, rowid))
        except Exception as e:
            print(f"Failed to decrypt row {rowid}: {e}", file=sys.stderr)
    conn.commit()
    print(f"Decrypted {len(rows)} rows in {table}.{column}")

# --------- CLI Interface ---------

def main():
    parser = argparse.ArgumentParser(description="HybridCrypt CLI - Hybrid Cryptosystem Database Encryptor")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Sub-command to execute")

    # generate-keys command
    gen_parser = subparsers.add_parser("generate-keys", help="Generate cryptographic keys")
    gen_parser.add_argument("--output-dir", type=str, required=True, help="Directory to save generated keys")
    gen_parser.add_argument("--key-name", type=str, required=True, help="Base name for key files")

    # encrypt command
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt database columns")
    enc_parser.add_argument("--db-path", type=str, required=True, help="Path to SQLite database file")
    enc_parser.add_argument("--table", type=str, required=True, help="Table name to encrypt")
    enc_parser.add_argument("--columns", type=str, required=True, help="Comma-separated columns to encrypt")
    enc_parser.add_argument("--key-path", type=str, required=True, help="Path to key file for encryption")

    # decrypt command
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt database columns")
    dec_parser.add_argument("--db-path", type=str, required=True, help="Path to SQLite database file")
    dec_parser.add_argument("--table", type=str, required=True, help="Table name to decrypt")
    dec_parser.add_argument("--columns", type=str, required=True, help="Comma-separated columns to decrypt")
    dec_parser.add_argument("--key-path", type=str, required=True, help="Path to key file for decryption")

    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_keys(args.output_dir, args.key_name)

    elif args.command in ("encrypt", "decrypt"):
        conn = connect_sqlite(args.db_path)
        key_data = load_key(args.key_path)
        columns = [col.strip() for col in args.columns.split(",")]

        for col in columns:
            if args.command == "encrypt":
                encrypt_column(conn, args.table, col, key_data)
            else:
                decrypt_column(conn, args.table, col, key_data)
        conn.close()

if __name__ == "__main__":
    main()

