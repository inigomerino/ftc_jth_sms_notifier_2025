#!/usr/bin/env python3

import os
import sys
import bcrypt
import getpass
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

# Connect to MongoDB (Make sure MongoDB is running)
client = MongoClient(os.getenv('MONGO_SRV'))
db = client[ os.getenv('MONGO_DB') ]

def create_superadmin():

    # Prompt user for username
    username = input("Enter the username for the admin user: ")

    # Prompt user for password (hide input)
    pwd1 = getpass.getpass("Enter the password for the superadmin: ")
    pwd2 = getpass.getpass("Re-enter the password: ")

    # Check that both entries match
    if pwd1 != pwd2:
        print("[ERROR] Passwords do not match. Exiting.")
        return

    # Check if superadmin already exists
    existing = db['admins'].find_one({"username": username})
    if existing:
        print(f"[INFO] A user named '{username}' already exists in the database.")
        return

    # Hash the password for secure storage
    hashed_password = bcrypt.hashpw(pwd1.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Create the superadmin user document
    superadmin_user = {
        "username"  : username,
        "password"  : hashed_password,
        "role"      : "super_admin"
    }

    # Insert into admins collection
    db['admins'].insert_one(superadmin_user)

    print("[SUCCESS] Superadmin user created.")

if __name__ == "__main__":
    create_superadmin()