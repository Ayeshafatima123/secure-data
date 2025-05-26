import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Set Streamlit page
st.set_page_config(page_title="🛡️ Secure Data Encryption System", layout="centered")

st.title("🛡️ Secure Data Encryption System")

# Sidebar for method selection
method = st.sidebar.selectbox("Choose Encryption Method", ["Symmetric (Fernet)", "Asymmetric (RSA)"])

# ---------------------- SYMMETRIC ENCRYPTION ----------------------
if method == "Symmetric (Fernet)":
    st.subheader("🔐 Symmetric Encryption with Fernet")

    key = st.text_input("Enter Fernet Key (leave blank to generate new key)", type="password")

    if not key:
        key = Fernet.generate_key()
        st.success("New Fernet key generated.")
        st.code(key.decode(), language="text")

    fernet = Fernet(key)

    action = st.radio("Choose Action", ["Encrypt", "Decrypt"])

    data = st.text_area("Enter Text")

    if st.button("Run"):
        if action == "Encrypt":
            encrypted = fernet.encrypt(data.encode())
            st.success("Encrypted Text:")
            st.code(encrypted.decode())
        else:
            try:
                decrypted = fernet.decrypt(data.encode()).decode()
                st.success("Decrypted Text:")
                st.code(decrypted)
            except:
                st.error("Invalid key or encrypted text.")

# ---------------------- ASYMMETRIC ENCRYPTION ----------------------
else:
    st.subheader("🔐 Asymmetric Encryption with RSA")

    key_action = st.radio("Key Management", ["Generate New Keys", "Use Existing Keys"])

    if key_action == "Generate New Keys":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        st.download_button("🔻 Download Private Key", pem_private, file_name="private_key.pem")
        st.download_button("🔻 Download Public Key", pem_public, file_name="public_key.pem")
    else:
        pub_key = st.file_uploader("Upload Public Key (for encryption)", type=["pem"])
        priv_key = st.file_uploader("Upload Private Key (for decryption)", type=["pem"])

    action = st.radio("Choose Action", ["Encrypt", "Decrypt"])
    data = st.text_area("Enter Text")

    if st.button("Run"):
        try:
            if action == "Encrypt" and pub_key:
                public_key = serialization.load_pem_public_key(pub_key.read())
                encrypted = public_key.encrypt(
                    data.encode(),
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                st.success("Encrypted Text (base64):")
                st.code(encrypted.hex())

            elif action == "Decrypt" and priv_key:
                private_key = serialization.load_pem_private_key(priv_key.read(), password=None)
                decrypted = private_key.decrypt(
                    bytes.fromhex(data),
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                st.success("Decrypted Text:")
                st.code(decrypted.decode())
            else:
                st.warning("Upload the correct key file.")
        except Exception as e:
            st.error(f"Error: {str(e)}")

    
