import streamlit as st
import hashlib
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
cipher = Fernet(KEY)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "logged_in" not in st.session_state:
    st.session_state.logged_in = True  


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()


def home_page():
    st.subheader("🏠 Welcome to the Secure Data System")
    st.markdown("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.markdown("Navigate using the sidebar.")

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

def login_page():
    st.subheader("🔑 Reauthorization Required")
    password = st.text_input("Enter master password to reauthorize:", type="password")

    if st.button("Login"):
        if password == "admin123":  
            st.success("✅ Login successful. Redirecting...")
            st.session_state.failed_attempts = 0
            st.session_state.logged_in = True
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password!")


st.sidebar.title("🔐 Secure Encryption App")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Go to:", menu)

if choice == "Home":
    home_page()
elif choice == "Store Data":
    store_data_page()
elif choice == "Retrieve Data":
    retrieve_data_page()
elif choice == "Login":
    login_page()
