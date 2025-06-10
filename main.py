import hashlib
import streamlit as st
from cryptography.fernet import Fernet

# ---------- 1️⃣ SESSION-STATE BOOTSTRAP ----------
if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.KEY)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "is_authorized" not in st.session_state:
    st.session_state.is_authorized = True

if "page" not in st.session_state:
    st.session_state.page = "Home"

# ---------- 2️⃣ UTILITY FUNCTIONS ----------
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(plaintext: str) -> str:
    return st.session_state.cipher.encrypt(plaintext.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> str | None:
    hashed = hash_passkey(passkey)
    entry = st.session_state.stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# ---------- 3️⃣ NAVIGATION ----------
PAGES = ("Home", "Store Data", "Retrieve Data", "Login")
page = st.sidebar.selectbox("Navigation", PAGES, index=PAGES.index(st.session_state.page))

st.title("🔒 Secure Data Encryption System")

# ---------- 4️⃣ PAGE: HOME ----------
if page == "Home":
    st.session_state.page = "Home"
    st.subheader("🏠 Welcome")
    st.markdown(
        """
        - **Store Data** → encrypt text with your private passkey  
        - **Retrieve Data** → decrypt by providing the same passkey  
        - Three wrong tries = temporary lockout (Login required)
        """
    )

# ---------- 5️⃣ PAGE: STORE DATA ----------
elif page == "Store Data":
    st.session_state.page = "Store Data"
    st.subheader("📂 Store Data")
    plaintext = st.text_area("Text to store")
    passkey = st.text_input("Choose a passkey", type="password")

    if st.button("Encrypt & Save"):
        if plaintext and passkey:
            encrypted = encrypt_data(plaintext)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hash_passkey(passkey),
            }
            st.success("Stored! Copy the ciphertext below (you'll need it to retrieve):")
            st.code(encrypted, language="text")
        else:
            st.error("Both fields are required.")

# ---------- 6️⃣ PAGE: RETRIEVE DATA ----------
elif page == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 or not st.session_state.is_authorized:
        st.warning("🔒 Too many failed attempts — please log in again.")
        st.session_state.page = "Login"
        st.experimental_rerun()

    st.session_state.page = "Retrieve Data"
    st.subheader("🔍 Retrieve Data")
    ciphertext = st.text_area("Paste the encrypted text")
    passkey = st.text_input("Enter passkey", type="password")

    if st.button("Decrypt"):
        if ciphertext and passkey:
            plaintext = decrypt_data(ciphertext, passkey)
            if plaintext is not None:
                st.success("✅ Decrypted text")
                st.code(plaintext, language="text")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("Redirecting to Login …")
                    st.session_state.page = "Login"
                    st.experimental_rerun()
        else:
            st.error("Both fields are required.")

# ---------- 7️⃣ PAGE: LOGIN ----------
elif page == "Login":
    st.session_state.page = "Login"
    st.subheader("🔑 Re-authorize")
    st.info("Enter the **master password** to reset your failed-attempt counter.")
    pwd = st.text_input("Master password", type="password")
    if st.button("Login"):
        if pwd == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.is_authorized = True
            st.success("Logged in! You may now decrypt again.")
            st.session_state.page = "Retrieve Data"
            st.rerun()
        else:
            st.session_state.is_authorized = False
            st.error("Incorrect master password.")
