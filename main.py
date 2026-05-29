import os
import bcrypt
import psycopg2
import random
from dotenv import load_dotenv
from flask import Flask, request

load_dotenv()
app = Flask(__name__)

db_url = os.getenv("DB_CONNECTION")


def get_db_connection():
    return psycopg2.connect(db_url)


def gen_account_number():
    return str(random.randint(1000000000, 9999999999))


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json

    name = data.get("username")
    password = data.get("password")
    transaction_pin = data.get("transaction_pin")

    if not name or len(name) < 2 or len(name) > 25:
        return {"msg": "invalid name"}, 400

    if not password or len(password) < 4 or len(password) > 10:
        return {"msg": "invalid password"}, 400

    if not transaction_pin or len(transaction_pin) != 6:
        return {"msg": "PIN must be 6 digits"}, 400

    conn = get_db_connection()
    cursor = conn.cursor()

    account_number = gen_account_number()

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    pin_hash = bcrypt.hashpw(
        transaction_pin.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    cursor.execute("""
        INSERT INTO users (user_name, password_hash, transaction_pin, account_number)
        VALUES (%s, %s, %s, %s)
    """, (name, password_hash, pin_hash, account_number))

    conn.commit()
    conn.close()

    return {
        "msg": "account created",
        "account_number": account_number
    }, 201


# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json

    name = data.get("name")
    password = data.get("password")

    if not name or not password:
        return {"msg": "missing fields"}, 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT password_hash, balance, account_number
        FROM users
        WHERE user_name = %s
    """, (name,))

    user = cursor.fetchone()
    conn.close()

    if not user:
        return {"msg": "user not found"}, 404

    password_hash, balance, account_number = user

    if not bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8")
    ):
        return {"msg": "wrong password"}, 401

    return {
        "name": name,
        "balance": float(balance),
        "account_number": account_number
    }, 200


# ---------------- DEPOSIT ----------------
@app.route("/deposit", methods=["POST"])
def deposit():
    data = request.json

    amount = float(data.get("amount"))
    account_number = data.get("account_number")
    deposit_pin = data.get("deposit_pin")

    if not amount or not account_number or not deposit_pin:
        return {"msg": "missing fields"}, 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT transaction_pin
        FROM users
        WHERE account_number = %s
    """, (account_number,))

    result = cursor.fetchone()

    if not result:
        conn.close()
        return {"msg": "account not found"}, 404

    pin_hash = result[0]

    if not bcrypt.checkpw(
        deposit_pin.encode("utf-8"),
        pin_hash.encode("utf-8")
    ):
        conn.close()
        return {"msg": "wrong pin"}, 401

    cursor.execute("""
        UPDATE users
        SET balance = balance + %s
        WHERE account_number = %s
        RETURNING balance
    """, (amount, account_number))

    new_balance = cursor.fetchone()[0]

    conn.commit()
    conn.close()

    return {"balance": float(new_balance)}, 200


# ---------------- TRANSFER ----------------
@app.route("/transfer", methods=["POST"])
def transfer():
    data = request.json

    amount = float(data.get("amount"))
    sender_name = data.get("name")
    sender_acc = data.get("sender_acc_number")
    receiver_acc = data.get("receiver_acc_number")

    if not sender_name or not sender_acc or not receiver_acc or not amount:
        return {"msg": "missing fields"}, 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # -------- sender --------
    cursor.execute("""
        SELECT balance
        FROM users
        WHERE user_name = %s AND account_number = %s
    """, (sender_name, sender_acc))

    sender = cursor.fetchone()

    if not sender:
        conn.close()
        return {"msg": "sender not found"}, 404

    sender_balance = sender[0]

    if sender_balance < amount:
        conn.close()
        return {"msg": "insufficient balance"}, 400

    # -------- receiver --------
    cursor.execute("""
        SELECT account_number
        FROM users
        WHERE account_number = %s
    """, (receiver_acc,))

    receiver = cursor.fetchone()

    if not receiver:
        conn.close()
        return {"msg": "receiver not found"}, 404

    # -------- deduct sender --------
    cursor.execute("""
        UPDATE users
        SET balance = balance - %s
        WHERE account_number = %s
    """, (amount, sender_acc))

    # -------- add receiver --------
    cursor.execute("""
        UPDATE users
        SET balance = balance + %s
        WHERE account_number = %s
    """, (amount, receiver_acc))

    conn.commit()
    conn.close()

    return {"msg": "transfer successful"}, 200


# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)