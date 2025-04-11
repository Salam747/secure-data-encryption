import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import secrets

# ✅ Random encryption key session mein save kar rahe hain
if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.KEY)

# ✅ Store karne ke liye dictionary (Passkey hash aur encrypted data store karna)
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# ✅ Failed attempts track karne ke liye
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# 🔐 Passkey ko hash karne ka function
def hash_passkey(passkey):
    """Passkey ko hash karne ka function"""
    return hashlib.sha256(passkey.encode()).hexdigest()

# 📦 Data ko encrypt karne ka function
def encrypt_data(data, passkey):
    """Data ko encrypt karne ka function"""
    hashed_passkey = hash_passkey(passkey)
    encrypted = st.session_state.cipher.encrypt(data.encode()).decode()

    # Store encrypted data with hashed passkey
    st.session_state.stored_data[hashed_passkey] = {
        "encrypted_data": encrypted,
        "hashed_passkey": hashed_passkey,
    }
    return encrypted

# 🔓 Data ko decrypt karne ka function
def decrypt_data(encrypted_data, passkey):
    """Encrypted data ko decrypt karne ka function"""
    try:
        hashed_passkey = hash_passkey(passkey)

        # 💡 Dictionary mein passkey ke hash se check kar rahe hain
        if hashed_passkey in st.session_state.stored_data:
            saved_data = st.session_state.stored_data[hashed_passkey]

            # 💡 Agar encrypted_data match kare
            if saved_data["encrypted_data"] == encrypted_data:
                decrypted = st.session_state.cipher.decrypt(encrypted_data.encode()).decode()
                st.session_state.failed_attempts = 0
                return decrypted

        # ❌ Match nahi hua
        st.session_state.failed_attempts += 1
        return None

    except Exception as e:
        st.session_state.failed_attempts += 1
        return None

# 🧭 Streamlit config aur sidebar menu
st.set_page_config(page_title="Secure Data App", page_icon="🔐")
st.title("🔐 Secure Data Encryption System")

menu = ["🏠 Home", "🛡️ Encrypt", "🔓 Decrypt", "🔑 Login"]
choice = st.sidebar.selectbox("📋 Menu", menu)

# 🏠 Home Page
if choice == "🏠 Home":
    st.subheader("👋 Welcome to the Encryption System")
    st.write("🔐 Encrypt & Decrypt sensitive data securely.")
    st.write("📂 Use sidebar for options.")

# 🛡️ Encrypt Page
elif choice == "🛡️ Encrypt":
    st.subheader("🛡️ Encrypt Your Data")
    data = st.text_area("📝 Enter your data:")
    passkey = st.text_input("🔑 Enter passkey:", type="password")

    # 🎲 Option to generate a new passkey
    if st.button("🎲 Generate Passkey"):
        passkey = secrets.token_urlsafe(16)  # Random passkey generation
        st.write(f"✅ Generated Passkey: `{passkey}`")

    # 🔐 Encrypt button
    if st.button("🔐 Encrypt"):
        if data and passkey:
            encrypted = encrypt_data(data, passkey)  # Encrypt data with the passkey

            st.success("✅ Data encrypted successfully!")
            st.code(encrypted, language="text")  # Display encrypted data
        else:
            st.error("⚠️ Please enter both data and passkey.")

# 🔓 Decrypt Page
elif choice == "🔓 Decrypt":
    st.subheader("🔓 Decrypt Encrypted Data")
    encrypted_data = st.text_input("🔒 Enter encrypted data:")
    passkey = st.text_input("🔑 Enter your passkey:", type="password")

    # Preventing too many failed attempts
    if st.session_state.failed_attempts >= 3:
        st.warning("🚫 Too many failed attempts. Please reauthorize.")
        # Directly re-run to reset the page
        st.session_state.failed_attempts = 0
        st.experimental_rerun()

    # 🔓 Decrypt button
    if st.button("🔓 Decrypt"):
        if encrypted_data and passkey:
            decrypted = decrypt_data(encrypted_data, passkey)  # Decrypt the data
            if decrypted:
                st.success("✅ Decryption Successful!")
                st.code(decrypted, language="text")  # Display decrypted data
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey or data. {remaining} attempts remaining.")
        else:
            st.error("⚠️ Please enter both fields.")

# 🔑 Reauthorize Login
elif choice == "🔑 Login":
    st.subheader("🔐 Reauthorize Login")
    passkey = st.text_input("🔑 Enter your passkey to re-login:", type="password")

    # ✅ Reauthorize button
    if st.button("✅ Reauthorize"):
        hashed = hash_passkey(passkey)
        if hashed in st.session_state.stored_data:
            st.session_state.failed_attempts = 0
            st.success("🔓 Access restored!")
            st.experimental_rerun()  # Re-run to go back to the home page
        else:
            st.error("❌ Invalid passkey.")

# 📝 Footer with credit
st.markdown("---")
st.markdown("<center>Built with ❤️ by Abdul Salam</center>", unsafe_allow_html=True)
