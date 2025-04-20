import streamlit as st
import hashlib
from cryptography.fernet import Fernet
from key_handler import load_or_create_key

KEY = load_or_create_key()
cipher = Fernet(KEY)

if "users" not in st.session_state:
    st.session_state.users = {}

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "current_user" not in st.session_state:
    st.session_state.current_user = None


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Home page
def home_page():
    st.subheader("🏠 Welcome to the Secure Data System")
    if st.session_state.logged_in:
        st.write(f"Hello, {st.session_state.current_user}!")
    else:
        st.write("You are not logged in. Please log in or sign up.")

# Sign-Up page
def signup_page():
    st.subheader("📝 Create Account")

    username = st.text_input("Choose a username:")
    password = st.text_input("Choose a password:", type="password")
    confirm_password = st.text_input("Confirm password:", type="password")

    if st.button("Sign Up"):
        if username and password:
            if password == confirm_password:
                
                st.session_state.users[username] = hash_passkey(password)
                st.success("✅ Account created successfully! You can now log in.")
            else:
                st.error("❌ Passwords do not match.")
        else:
            st.error("⚠️ Please fill out all fields.")

# Login page
def login_page():
    st.subheader("🔑 Log In")

    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        if username in st.session_state.users:
            stored_password_hash = st.session_state.users[username]
            if stored_password_hash == hash_passkey(password):
                st.success(f"✅ Welcome {username}!")
                st.session_state.logged_in = True
                st.session_state.current_user = username
                st.session_state.failed_attempts = 0
                st.info("🎉 Login successful! Please use the sidebar to navigate.")
            else:
                st.error("❌ Incorrect password.")
        else:
            st.error("❌ Username not found. Please sign up.")

def store_data_page():
    st.subheader("📂 Store Data")
    data = st.text_area("Enter the data to encrypt:")
    passkey = st.text_input("Enter your secret passkey:", type="password")

    if st.button("Encrypt & Store"):
        if data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(data)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please enter both data and passkey.")

# Retrieve 
def retrieve_data_page():
    if not st.session_state.logged_in:
        st.warning("🔐 You must reauthorize first.")
        st.stop()

    st.subheader("🔍 Retrieve Data")
    encrypted_input = st.text_area("Paste the encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            hashed_input = hash_passkey(passkey)
            match_found = False

            for item in st.session_state.stored_data.values():
                if item["encrypted_text"] == encrypted_input:
                    if item["passkey"] == hashed_input:
                        decrypted = decrypt_data(encrypted_input)
                        st.success(f"✅ Decrypted Data: {decrypted}")
                        st.session_state.failed_attempts = 0
                        match_found = True
                        break

            if not match_found:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page...")
                    st.session_state.logged_in = False
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please provide both encrypted data and passkey.")

st.sidebar.title("🔐 Secure Encryption App")
menu = ["Home", "Sign Up", "Log In", "Store Data", "Retrieve Data"]
choice = st.sidebar.radio("Go to:", menu)

if choice == "Home":
    home_page()
elif choice == "Sign Up":
    signup_page()
elif choice == "Log In":
    login_page()
elif choice == "Store Data":
    store_data_page()
elif choice == "Retrieve Data":
    retrieve_data_page()
