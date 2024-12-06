import streamlit as st
import pandas as pd
import hashlib
from cryptography.fernet import Fernet
import io
import spacy

# Load spaCy model
nlp = spacy.load("en_core_web_sm")

# Helper function to detect sensitive columns using NER
def ner_detect_sensitive_columns(df):
    """
    Use NER to detect sensitive columns based on data values.
    """
    sensitive_labels = {"PERSON", "EMAIL", "GPE", "ADDRESS", "PHONE"}
    sensitive_columns = []

    for col in df.columns:
        # Take the top 5 and bottom 5 samples from the column
        sample_data = pd.concat([df[col].head(5), df[col].tail(5)], ignore_index=True).astype(str)

        for value in sample_data:
            # Apply spaCy NER to each value
            doc = nlp(value)
            if any(ent.label_ in sensitive_labels for ent in doc.ents):
                sensitive_columns.append(col)
                break  # If one value is sensitive, consider the entire column sensitive

    return list(set(sensitive_columns))

# Function to encrypt data (Reversible)
def encrypt_data(df, key):
    fernet = Fernet(key)
    encrypted_df = df.copy()
    sensitive_columns = ner_detect_sensitive_columns(df)
    for col in sensitive_columns:
        encrypted_df[col] = encrypted_df[col].astype(str).apply(lambda x: fernet.encrypt(x.encode()).decode())
    return encrypted_df, sensitive_columns

# Function to encrypt selected columns (Irreversible)
def irreversible_encrypt_data(df, columns, salt):
    encrypted_df = df.copy()
    for col in columns:
        encrypted_df[col] = encrypted_df[col].astype(str).apply(
            lambda x: hashlib.sha256((x + salt).encode()).hexdigest()
        )
    return encrypted_df

# Function to decrypt data
def decrypt_data(df, key):
    fernet = Fernet(key)
    decrypted_df = df.copy()
    sensitive_columns = ner_detect_sensitive_columns(df)
    for col in sensitive_columns:
        decrypted_df[col] = decrypted_df[col].astype(str).apply(lambda x: fernet.decrypt(x.encode()).decode())
    return decrypted_df

# Streamlit app
st.title("PII Encryption and Decryption Tool")

uploaded_file = st.file_uploader("Upload your tabular file (CSV or Excel)", type=["csv", "xlsx"])
option = st.radio("Select an action:", ["Reversible Encrypt", "Irreversible Encrypt", "Decrypt"])

if uploaded_file:
    # Read the file into a Pandas DataFrame
    if uploaded_file.name.endswith('.csv'):
        df = pd.read_csv(uploaded_file)
    else:
        df = pd.read_excel(uploaded_file)

    st.write("Uploaded Data:")
    st.dataframe(df)

    # Detect sensitive columns using NER
    sensitive_columns = ner_detect_sensitive_columns(df)
    st.write("Detected Sensitive Columns:", sensitive_columns)

    if option == "Reversible Encrypt":
        if st.button("Encrypt (Reversible)"):
            # Generate a new key
            key = Fernet.generate_key()
            encrypted_df, encrypted_columns = encrypt_data(df, key)

            # Add the encryption key only to the first row
            encrypted_df["encryption_key"] = ""
            encrypted_df.loc[0, "encryption_key"] = key.decode()

            st.success("Data encrypted successfully!")
            st.write("Encrypted Data (with embedded key):")
            st.dataframe(encrypted_df)
            st.write("Sensitive Columns Detected and Encrypted:", encrypted_columns)

            # Prepare file for download
            if uploaded_file.name.endswith(".csv"):
                csv_data = encrypted_df.to_csv(index=False).encode()
                st.download_button(
                    label="Download Encrypted Data (CSV)",
                    data=csv_data,
                    file_name="encrypted_data_with_key.csv",
                    mime="text/csv"
                )
            else:
                # Save as Excel
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
                    encrypted_df.to_excel(writer, index=False, sheet_name="Encrypted Data")
                st.download_button(
                    label="Download Encrypted Data (Excel)",
                    data=output.getvalue(),
                    file_name="encrypted_data_with_key.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

    elif option == "Irreversible Encrypt":
        columns = st.multiselect("Select columns to encrypt irreversibly:", options=df.columns)
        salt = st.text_input("Enter a salt value for hashing (ensure it's consistent for sharing purposes):", value="default_salt")

        if st.button("Encrypt (Irreversible)"):
            if columns:
                encrypted_df = irreversible_encrypt_data(df, columns, salt)
                st.success("Data irreversibly encrypted successfully!")
                st.write("Encrypted Data:")
                st.dataframe(encrypted_df)
                st.write("Columns Encrypted:", columns)
                st.download_button(
                    label="Download Encrypted Data",
                    data=encrypted_df.to_csv(index=False).encode(),
                    file_name="irreversible_encrypted_data.csv",
                    mime="text/csv"
                )
            else:
                st.warning("Please select at least one column to encrypt.")

    elif option == "Decrypt":
        key_input = st.text_input("Enter the decryption key:")
        if st.button("Decrypt"):
            try:
                if "encryption_key" in df.columns:
                    key_input = df["encryption_key"].iloc[0]  # Extract the embedded key
                    df = df.drop(columns=["encryption_key"])  # Remove the key column before decrypting

                decrypted_df = decrypt_data(df, key_input.encode())
                st.success("Data decrypted successfully!")
                st.write("Decrypted Data:")
                st.dataframe(decrypted_df)
                st.download_button(
                    label="Download Decrypted Data",
                    data=decrypted_df.to_csv(index=False).encode(),
                    file_name="decrypted_data.csv",
                    mime="text/csv"
                )
            except Exception as e:
                st.error(f"Decryption failed: {e}")
