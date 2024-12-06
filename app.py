import streamlit as st
import pandas as pd
import hashlib
from cryptography.fernet import Fernet
import io

# Set Streamlit page configuration
st.set_page_config(page_title="🔒 PII Encryption & Decryption Tool", page_icon="🔐", layout="wide")

import os
import requests
import json
import ast
 


def detectPII(input_text):
    # Retrieve environment variables
    API_KEY_GPT4 = st.secrets["general"]["API_KEY_GPT4"]
    API_KEY_GPT4 = os.getenv("API_KEY_GPT4")
    
    endpoint = os.getenv("ENDPOINT_URL", "https://idagptservice.openai.azure.com/")
    deployment = os.getenv("DEPLOYMENT_NAME", "gpt-4")
    prompt =f"""Here is a sample dataset which needs to find PII:  

{input_text}
Analyze the given dataset to identify all instances of Personally Identifiable Information (PII) except for primary names.
 Categorize the identified PII into three groups: (1) sensitive information requiring anonymization, 
 (2) information shareable with external organizations after authorization, and 
 (3) information that must be entirely excluded from sharing. For each identified PII, 
 classify and provide handling recommendations based on its frequency in the data and presence in key-value pairs.

Identify and flag high-frequency key-value pairs containing personal information. Include PII types such as address, email, phone number, credit card number, social security number, date of birth, financial information, salary, race, religion, caste, or any data that uniquely identifies a person. Exclude the main name but include secondary identifiers like surnames or name extensions.

Output the identified PII keys in this exact format:
['name', 'email', 'phone']
Do not include any explanations or additional text in the output.







"""
 

  
    GPT4V_ENDPOINT = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version=2024-05-01-preview"
    
    headers = {
        "Content-Type": "application/json",
        "api-key": API_KEY_GPT4,
    }
    
    payload = {
        "messages": [
            {
                "role": "system",
                "content": prompt
            }
        ],
        "temperature": 0.6,
        "top_p": 0.95
    }
    
    try:
        # Send the request to Azure OpenAI
        req = requests.post(GPT4V_ENDPOINT, headers=headers, json=payload)
        req.raise_for_status()  # Raises an HTTPError for bad responses
        
        # Parse response
        response = req.json()
        response_text = response["choices"][0]["message"]["content"]
        
        return response_text
    
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return "No recommendation"
    except (KeyError, IndexError) as e:
        print(f"Error in parsing response: {e}")
        return "No recommendation"
# Helper function to detect sensitive columns
def detect_sensitive_columns(df):
    sensitive_keywords = ['name', 'email', 'phone', 'address']
    return [col for col in df.columns if any(keyword in col.lower() for keyword in sensitive_keywords)]

# Function to encrypt data (Reversible) with a matching condition
def encrypt_data_with_match(df, key, match_dataset):
    fernet = Fernet(key)
    encrypted_df = df.copy()
    
    # Ensure only columns that exist in `df` are processed
    sensitive_columns = [col for col in match_dataset if col in encrypted_df.columns]
    
    for col in sensitive_columns:
        encrypted_df[col] = encrypted_df[col].astype(str).apply(
            lambda x: fernet.encrypt(x.encode()).decode() if pd.notna(x) else x  # Encrypt non-NaN values
        )
    
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
def decrypt_data(df, key,columns):
    fernet = Fernet(key)
    decrypted_df = df.copy()
    sensitive_columns = columns
    print(sensitive_columns)
    sensitive_columns= ast.literal_eval(columns)
    print(columns)
    
    for col in sensitive_columns:
        print(col)
        decrypted_df[col] = decrypted_df[col].apply(
            lambda x: fernet.decrypt(x.encode()).decode() if isinstance(x, str) and x.startswith("gAAAA") else x
        )
    return decrypted_df

# Sidebar Navigation
st.sidebar.title("🔒 Navigation")
page = st.sidebar.radio("Choose an operation", ["Home", "PII Operations", "About"])

# Home Page
if page == "Home":
    st.title("🔐 Welcome to the PII Encryption and Decryption Tool")
    st.image("image1.jpg", use_container_width=True)

    st.markdown("""
    ### 🔍 **Secure Sensitive Data**
    This tool offers advanced encryption and anonymization techniques to handle PII (Personally Identifiable Information).

    #### 🛠 **Features:**
    - 🔒 **Reversible Encryption**: Secure sensitive data while allowing decryption.
    - 🚫 **Irreversible Encryption**: Anonymize data permanently using hashing.
    - 🔓 **Decryption**: Access encrypted data securely with a valid key.

    ### How to Use:
    1. **Upload a file**: Choose your file in the provided uploader.
    2. **Select your action**: Choose whether you want to anonymize or encrypt the data.
    3. **Download your result**: Download the anonymized/encrypted data or decrypted data.
 
    **Get started by choosing an operation from the sidebar!🚀**

   
    """)

# PII Operations Page
elif page == "PII Operations":
    st.title("🔒 PII Operations")

    uploaded_file = st.file_uploader("📂 Upload your file (CSV or Excel)", type=["csv", "xlsx"])
    option = st.radio("🛠 Choose an action:", ["Reversible Encrypt", "Irreversible Encrypt", "Decrypt"])

    if uploaded_file:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)

        st.write("### 🔎 Uploaded Data:")
        st.dataframe(df)

        if option == "Reversible Encrypt":
            if st.button("🔒 Encrypt (Reversible)"):
                array_of_dicts = df.to_dict(orient="records")
                match_dataset = detectPII(array_of_dicts[:10])
                
                list = ast.literal_eval(match_dataset)
                print(list)

                # Generate a new key
                key = Fernet.generate_key()
                encrypted_df, sensitive_columns = encrypt_data_with_match(df, key, list)

                st.success("🔑 Data encrypted successfully!")
                st.write("#### 🔐 Encrypted Data:")
                st.dataframe(encrypted_df)
                st.write("#### 📃 Sensitive Columns Encrypted:", sensitive_columns)

                # Save encrypted data and key in separate sheets
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
                    encrypted_df.to_excel(writer, index=False, sheet_name="Encrypted Data")
                    pd.DataFrame({"Encryption Key": [key.decode()],"Columns":[list]}).to_excel(writer, index=False, sheet_name="Encryption Key")

                st.download_button(
                    label="📥 Download Encrypted Data (Excel)",
                    data=output.getvalue(),
                    file_name="encrypted_data.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

        elif option == "Irreversible Encrypt":
            columns = st.multiselect("🔘 Select columns to encrypt irreversibly:", options=df.columns)
            salt = st.text_input("🧂 Enter a salt value for hashing:")

            if st.button("🔒 Encrypt (Irreversible)"):
                encrypted_df = irreversible_encrypt_data(df, columns, salt)
                st.success("✅ Data irreversibly encrypted successfully!")
                st.write("#### 🔐 Encrypted Data:")
                st.dataframe(encrypted_df)

        elif option == "Decrypt":
            st.subheader("🔓 Decrypt Data")
            if "authenticated" not in st.session_state:
                st.session_state.authenticated = False

            # Authentication step
            if not st.session_state.authenticated:
                username = st.text_input("Enter username:", value="", type="default")
                password = st.text_input("Enter password:", value="", type="password")

                if st.button("Authenticate"):
                    if username == "admin" and password == "123":
                        st.success("Authentication successful! You can now decrypt the data.")
                        st.session_state.authenticated = True
                    else:
                        st.error("Authentication failed! Please check your username and password.")
            if st.session_state.authenticated:
                st.subheader("Decryption Section")
                key_input = st.text_input("Enter the decryption key / Directly Decrypt if key present in Excel")
                if st.button("🔓 Decrypt"):
                    try:
                        # Read key from the Encryption Key sheet
                        with pd.ExcelFile(uploaded_file) as xls:
                            key_sheet = pd.read_excel(xls, sheet_name="Encryption Key")
                            print(key_sheet)
                            key_input = key_sheet["Encryption Key"][0]
                            columns=key_sheet["Columns"][0]
                            print(columns)
                            df = pd.read_excel(xls, sheet_name="Encrypted Data")

                        decrypted_df = decrypt_data(df, key_input.encode(),columns)
                        st.success("✅ Data decrypted successfully!")
                        st.write("#### 🔓 Decrypted Data:")
                        st.dataframe(decrypted_df)

                        # Prepare decrypted data for download
                        st.download_button(
                            label="📥 Download Decrypted Data (Excel)",
                            data=decrypted_df.to_csv(index=False).encode(),
                            file_name="decrypted_data.csv",
                            mime="text/csv"
                        )
                    except Exception as e:
                        st.error(f"❌ Decryption failed: {e}")

# About Page
elif page == "About":
    st.title("ℹ️ About This Tool")
    st.markdown("""
    This tool is designed to securely manage PII data with features like reversible and irreversible encryption, and decryption.

    **🔧 Developed for organizations to ensure secure and compliant data handling.**
    """)
