# CertiDigitalPy

A secure web application for issuing and verifying digital diplomas using cryptographic signatures and X.509 certificates.

## 📋 Description

CertiDigitalPy is a Streamlit-based Python web application that provides a complete solution for digital diploma certification. In today's digital age, validating academic credentials is crucial, and this application offers institutions a secure way to issue diplomas with robust digital signatures while allowing anyone to verify the authenticity of received diplomas.

The application uses unique identifiers to associate diplomas with participants and stores certification records in a Firestore database for secure querying and verification.

## ✨ Key Features

### 🎓 Issue Certified Diplomas
- **Multi-format Support**: Upload diplomas in PDF, PNG, or JPG format
- **Secure Identification**: Enter participant's unique identifier
- **Cryptographic Hashing**: Generate SHA-256 hash of the document
- **Digital Signing**: Sign the hash using organization's RSA private key
- **Cloud Storage**: Securely store details (ID, hash, signature, issuer's certificate) in Google Firestore
- **File Downloads**: Download signature file (.sig) and issuer's public certificate (.pem)

### 🔍 Verify Authenticity
- **Query by ID**: Search the database for certificates issued for a specific ID
- **Signature Verification**: Verify stored digital signature against stored hash
- **Content Integrity**: Upload original diploma to compare current hash with registered one
- **Local Verification**: Verify diplomas offline by uploading original document, signature file (.sig), and issuer's certificate (.pem)

### 🔐 Cryptographic Security
- **RSA Encryption**: Use of RSA key pairs (2048 bits) for signing
- **X.509 Certificates**: Self-signed certificates for issuing organization
- **Password Protection**: Secure the organization's private key with password protection

### 🖥️ User-Friendly Interface
- **Streamlit Framework**: Intuitive and responsive user experience
- **Easy Navigation**: Simple menu system for different operations

## 🛠️ Technologies Used

- **Python 3.x**
- **Streamlit** - Web application framework
- **Cryptography** (pyca/cryptography) - Cryptographic operations
- **Google Cloud Firestore** - Document database
- **google-cloud-firestore & google-auth** - Google Cloud integration
- **streamlit-option-menu** - Enhanced navigation menu

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Google Cloud Platform account with Firestore enabled
- GCP service account credentials with Firestore permissions (JSON file)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ClaudioGlez21/CertiDigitalPy.git
   cd CertiDigitalPy
   ```
   *(Replace with your actual repository URL)*

2. **Create and activate a virtual environment (recommended):**
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

#### Firestore Credentials Setup

**Option A: Deploying to Streamlit Cloud (Recommended)**
- Set up a secret in Streamlit Cloud named `firestore` with the JSON content
- Refer to the application's source code for the exact TOML secret structure

**Option B: Local Development**
- Download the JSON key file for your Google Cloud service account
- Rename it to `firestore_credentials.json` and place in the project's root directory
- **Important**: Add `firestore_credentials.json` to your `.gitignore` file

#### Organization Key Generation
- On first run, `organizational_private_key.pem` (encrypted private key) and `organizational_certificate.pem` (public certificate) will be generated automatically
- The default password for the private key is defined in the source code (`ORG_KEY_PASSWORD`)
- **Security Note**: Store `organizational_private_key.pem` and its password securely

## 🏃‍♂️ Running the Application

Execute the Streamlit application:
```bash
streamlit run app.py
```

Open your browser and navigate to the address Streamlit indicates (usually `http://localhost:8501`)

## 📖 Usage

### Issuing a Certificate

1. Navigate to the **"Issue Certificate"** section
2. Enter the participant's unique identifier
3. Upload the diploma file (PDF, PNG, or JPG)
4. Click **"Generate and Sign Certificate"**
5. If successful, download:
   - Digital signature file (`.sig`)
   - Issuing organization's public certificate (`.pem`)

### Verifying a Certificate

Navigate to the **"Verify Certificate"** section and choose one of two options:

#### Option 1: Query by ID
1. Enter the participant ID
2. Optionally upload the original diploma for hash comparison
3. Click **"Search and Verify by ID"**

#### Option 2: Local File Verification
1. Upload the original diploma
2. Upload the signature file (`.sig`)
3. Upload the issuer's certificate (`.pem`)
4. Click **"Verify Files Locally"**

## 🔒 Security Considerations

- **Private Key Protection**: The `organizational_private_key.pem` file and its password are critical. In production, use HSMs or cloud-based key management services
- **Certificate Authority**: This demonstration uses self-signed certificates. For production systems, use certificates issued by recognized Certificate Authorities (CA)
- **Input Validation**: Implement comprehensive input validation for production environments
- **Access Control**: Ensure proper access controls for sensitive operations

## 🚀 Future Enhancements

- Integration with real Certificate Authority (CA)
- User and role management system
- Certificate revocation capabilities
- Email notifications for certificate issuance
- Administrative panel for system management
- Internationalization support
- Comprehensive event auditing
- Mobile application support

## 📄 License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

If you encounter any issues or have questions, please create an issue in the GitHub repository.

---

**Made with ❤️ by [Your Name/Team Name]**