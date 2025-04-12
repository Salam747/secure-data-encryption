import streamlit as st
import time
from utils import load_data, save_data, encrypt_text, decrypt_text, hash_passkey, verify_passkey

# 🔄 For storing global variables
stored_data = load_data()
failed_attempts = 0
lockout_start = None
lockout_time = 60  # seconds

# 📁 Set default page
if "page" not in st.session_state:
    st.session_state.page = "home"

# 🧑 For storing username
if "username" not in st.session_state:
    st.session_state.username = None

# 🟩 Login Page UI
def login_page():
    st.title("🔑 Login Page")
    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("➡️ Login"):
        if username in stored_data:
            if verify_passkey(password, stored_data[username]["password"]):
                st.session_state.username = username
                st.success("🟢 Successfully Logged In")
                st.session_state.page = "dashboard"
            else:
                st.error("❌ Incorrect password")
        else:
            st.warning("🆕 User not found, please sign up")

    if st.button("📝 Sign Up"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists")
            else:
                stored_data[username] = {
                    "password": hash_passkey(password),
                    "data": {}
                }
                save_data(stored_data)
                st.success("✅ Signup complete, please log in")

# 🏠 Dashboard page
def dashboard():
    st.title(f"🙋 Welcome {st.session_state.username}")
    if st.button("➕ Save New Data"):
        st.session_state.page = "store"
    if st.button("🔍 View Data"):
        st.session_state.page = "retrieve"
    if st.button("🚪 Logout"):
        st.session_state.username = None
        st.session_state.page = "login"

# 💾 Data Save Page
def store_data():
    st.title("📥 Save New Info")
    key = st.text_input("📝 Enter a name for your data (e.g., note1)")
    text = st.text_area("✍️ Write your content here")
    passkey = st.text_input("🔐 Enter your secret passkey", type="password")

    if st.button("🔐 Encrypt and Save"):
        if key and text and passkey:
            encrypted = encrypt_text(text, passkey)
            hashed_key = hash_passkey(passkey)
            stored_data[st.session_state.username]["data"][key] = {
                "encrypted_text": encrypted,
                "passkey": hashed_key
            }
            save_data(stored_data)
            st.success("✅ Successfully saved")
        else:
            st.warning("⚠️ All fields are required")

    if st.button("🔙 Go Back"):
        st.session_state.page = "dashboard"

# 🔓 Data Retrieve Page
def retrieve_data():
    global failed_attempts, lockout_start

    st.title("📤 Retrieve Data")
    key = st.text_input("📝 Enter the name of your data (e.g., note1)")
    passkey = st.text_input("🔑 Enter passkey", type="password")

    if failed_attempts >= 3:
        if lockout_start is None:
            lockout_start = time.time()
        elif time.time() - lockout_start < lockout_time:
            st.warning(f"⏳ Please wait: {int(lockout_time - (time.time() - lockout_start))} sec")
            return
        else:
            failed_attempts = 0
            lockout_start = None

    if st.button("🛠️ Decrypt"):
        user_data = stored_data[st.session_state.username]["data"]
        if key in user_data:
            if verify_passkey(passkey, user_data[key]["passkey"]):
                decrypted = decrypt_text(user_data[key]["encrypted_text"], passkey)
                st.success("✅ Here is your data:")
                st.code(decrypted)
                failed_attempts = 0
            else:
                failed_attempts += 1
                st.error(f"❌ Incorrect passkey. Attempt: {failed_attempts}/3")
        else:
            st.warning("❗ Key does not exist")

    if st.button("🔙 Go Back to Dashboard"):
        st.session_state.page = "dashboard"

# 🔀 Page Routing
if st.session_state.page == "login":
    login_page()
elif st.session_state.page == "dashboard":
    dashboard()
elif st.session_state.page == "store":
    store_data()
elif st.session_state.page == "retrieve":
    retrieve_data()
else:
    login_page()
