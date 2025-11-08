#!/usr/bin/env python3
"""
make_admin.py
Create a person with an admin password and add into admin table.
Run: python make_admin.py
"""

import os, hashlib, mysql.connector, getpass, binascii

# EDIT these DB settings if needed:
DB = {
    "host": "localhost",
    "user": "root",
    "password": "1234",
    "database": "bank",
    "autocommit": True
}

def hash_password(password: str):
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt + h

def main():
    print("Create admin user (will insert into person and admin tables).")
    email = input("Admin email (e.g. admin@example.com): ").strip() or "admin@example.com"
    name = input("Admin name (e.g. Admin): ").strip() or "Admin"
    password = getpass.getpass("Admin password (input hidden): ").strip()
    if not password:
        print("Empty password — aborted.")
        return
    hashed = hash_password(password)
    hexhash = binascii.hexlify(hashed).decode()

    conn = mysql.connector.connect(**DB)
    cur = conn.cursor()
    try:
        # insert person
        cur.execute("INSERT INTO person (user_id, name, email, password_hash, role) VALUES (%s,%s,%s,%s,%s)",
                    (email, name, email, mysql.connector.Binary(hashed), 'admin'))
        person_id = cur.lastrowid
        # insert admin marker
        cur.execute("INSERT INTO admin (person_id) VALUES (%s)", (person_id,))
        conn.commit()
        print("Admin created with person_id:", person_id)
    except mysql.connector.IntegrityError as e:
        conn.rollback()
        print("Integrity error:", e)
        print("If email exists, consider updating existing person and inserting into admin table.")
    except Exception as e:
        conn.rollback()
        print("Error:", e)
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    main()
