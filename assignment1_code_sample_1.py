import os
import pymysql
from urllib.request import urlopen

# A09 security logging or monitoring failure
# https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures/

# A02 Cryptographic failue 
# Import OWASP Certfied Hasher
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
# Argon automatically salts
from argon2 import PasswordHasher

# Initialize PasswordHasher
ph = PasswordHasher()

# Hash the password
def hash_password(plain_password: str) -> str:
    return ph.hash(plain_password)

# Verify the hash and the password
def verify_password(stored_hash: str, plain_password: str) -> bool:
    try:
        return ph.verify(stored_hash, plain_password)
    except:
        print("Hash Mismatch Error")

# Security Misconfiguration A05
# should remove all hardcoded instances of credentials and keep in a secret file
# https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

# DELETED CREDENTIALS

# A03 Injection Failure
# Need to sanitize input, can use regex to limit user input
# followed owasp regex cheatsheet 
# https://owasp.org/www-community/OWASP_Validation_Regex_Repository
import re

def get_user_input():
    pattern = r"^[a-zA-Z]+(([',. -][a-zA-Z ])?[a-zA-Z]*)*$"
    user_input = input('Enter your name: ').strip()
    if re.fullmatch(pattern, user_input):
        return user_input
    print("Invalid name format")
        
# A03 Injection failure
# Should encrypt email transmission
# can use smtplib with smtp_ssl() or server.starttls()
# https://stackabuse.com/securing-your-email-sending-with-python-authentication-and-encryption/

import smtplib
from email.mime.text import MIMEText

# get user and password from environment
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_HOST = "smtp.gmail.com"
# uses ssl port
SMTP_PORT = 465

def send_email(to_email: str, subject: str, body: str) -> None:
    # Structured/Prepared statement
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.login(SMTP_USER, SMTP_PASS)
            # msg will only send as a string
            smtp.sendmail(SMTP_USER, [to_email], msg.as_string())
    except Exception as e:
        print("Email error:", e)

# A10 Server-Side Request Forgery
# HTTP url unsafe change to https
# can use validators + request and timeout the api request
# https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
import validators
import requests

def get_data():
    url = "https://secure-api.com/get-data"

    # Validate URL format
    if not validators.url(url):
        raise ValueError("Invalid URL")

    # Enforce HTTPS
    if not url.lower().startswith("https://"):
        raise ValueError("Insecure URL scheme")

    # Timeout requests after 5 seconds
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:

        raise RuntimeError(f"Request failed: {e}")


# A03 Injection failure
# Can use a prepared statement to limit input
# https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

def save_to_db(data: str) -> None:
    try:
        # % acts as a place holder, removed explicit {data} and {"Another Value"}
        query = "INSERT INTO mytable (column1, column2) VALUES (%s, %s)"

        # db_config not actually linked to anything here but it would have credentials
        connection = pymysql.connect(db_config)

        cursor = connection.cursor()
        cursor.execute(query, (data, "Another Value") )
        connection.commit()
        cursor.close()
        connection.close()

    except pymysql.MySQLError as e:
        print("Database error:", e)

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)
