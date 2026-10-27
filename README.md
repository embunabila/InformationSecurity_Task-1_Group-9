# Medimo: Personal Health Record

**Group 9 | Information Security (I)**

## Team Members

| No. | Student Name | Student ID |
|---:|---|---|
| 1 | Adelia Tanalina Yumna | 5025241078 |
| 2 | Almira Nayla Felisitha | 5025241014 |
| 3 | Embun Nabila Azzahra Rasendrya | 5025241009 |
| 4 | Nuha Usama Okbah | 5025241005 |

**Lecturer:** Dr. Baskoro Adi Pratomo, S.Kom., M.Kom., Ph.D.

**Course:** Information Security

---

## Project Overview

Medimo is a web-based Personal Health Record (PHR) application that allows users to securely store and manage their personal health information in one place. It is designed for people who need convenient access to their medical records, such as laboratory results, prescriptions, identity documents, and symptom videos during medical consultations.

The project demonstrates authentication, data ownership, encryption at rest, and integrity verification using AES, DES, and RC4.

## Features

- **User authentication:** Register, log in, and log out securely.
- **Health profile management:** Create and update personal health information, including date of birth, gender, contact information, allergies, health conditions, and routine medication.
- **Medical file management:** Upload, retrieve, download, and delete personal files.
- **Encryption at rest:** Store three independent encrypted copies of each supported record using AES, DES, and RC4.
- **Integrity verification:** Use HMAC-SHA256 to detect tampering before decryption.
- **Ownership enforcement:** Restrict access to records belonging to the authenticated user.
- **Upload size limits:** Support uploads with a maximum file size of 25 MiB.
- **CSRF protection:** Protect state-changing requests against cross-site request forgery.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript, Jinja |
| Database | SQLite |
| Cryptography | PyCryptodome |
| Password security | Werkzeug password hashing |
| Key derivation | HKDF-SHA256 |
| Integrity verification | HMAC-SHA256 |

## Encryption Design

Medimo uses three independent encrypted copies of each supported record to compare the processing cost and storage overhead of AES, DES, and RC4.

The three copies are **not layered encryption**. Each algorithm independently encrypts the same original data.

| Algorithm | Construction | Purpose |
|---|---|---|
| AES | AES-256-CBC with PKCS#7 padding | Primary algorithm for retrieving records |
| DES | DES-CBC with PKCS#7 padding | Legacy algorithm for comparison |
| RC4 | RC4 stream cipher | Legacy algorithm for comparison |

All three constructions use HMAC-SHA256 for integrity verification. AES and DES use fresh random initialization vectors (IVs), while RC4 does not require an IV or block padding.

A persistent 32-byte master key is loaded from the environment. HKDF-SHA256 derives separate encryption and authentication keys using random salts and algorithm-specific labels.

The encrypted envelopes include format information and authenticate the relevant header, record context, and ciphertext. The backend supplies the expected owner and item context during decryption to help prevent encrypted records from being substituted across users or items.

Authentication and ownership checks remain necessary even when cryptographic verification is enabled.

## Security Considerations and Limitations

Medimo is an academic prototype, not a production-ready medical records platform.

- **DES and RC4 are insecure legacy algorithms.** They are included to satisfy the assignment's comparison requirements, not recommended for protecting real medical data.
- **The application is not end-to-end encrypted.** The server holds the master key and can decrypt records.
- **Master key loss prevents recovery** of records encrypted with that key. Changing the key without a proper migration process also makes existing records inaccessible.
- **Storage overhead increases** because each record has three independent encrypted copies.
- **File processing uses memory.** Large uploads may require substantial memory because payloads and multiple encrypted copies are processed.
- **Rollback protection is limited.** Integrity verification detects unauthorized modifications but does not independently prevent an older, previously valid version of a record from being restored.
- **The prototype has limited deployment hardening.** It should not be used with real patient information or exposed publicly without further security review and testing.

Use dummy data when running or demonstrating this project.

## Getting Started

### Prerequisites

- Python 3.12 or a compatible Python version
- Git
- PowerShell on Windows, or an equivalent terminal on other operating systems

### 1. Clone the Repository

```bash
git clone https://github.com/embunabila/InformationSecurity_Task-1_Group-9.git
cd InformationSecurity_Task-1_Group-9
```

### 2. Create and Activate a Virtual Environment

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, you can allow activation scripts for the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Initialize the Database

```powershell
python db.py
```

### 5. Configure the Environment Variables

Generate a persistent Flask session secret and master key for local development:

```powershell
python -c "import secrets; from pathlib import Path; p=Path('.env.local'); p.write_text('SECRET_KEY='+secrets.token_hex(32)+'\nMASTER_KEY='+secrets.token_hex(32)+'\n', encoding='utf-8') if not p.exists() else print('Keys already exist; keeping the existing file.')"
```

Load the variables into the current PowerShell session:

```powershell
Get-Content .env.local | ForEach-Object {
    $name, $value = $_ -split '=', 2
    [Environment]::SetEnvironmentVariable($name, $value, 'Process')
}
```

**Important:**

- Keep `.env.local` private and never commit it to GitHub.
- Keep the same master key when reopening existing encrypted records.
- Do not regenerate the key if you need to access previously stored data.
- Store the keys securely and ensure `.env.local` is excluded from version control.

### 6. Run the Application

```powershell
python app.py
```

Open the application in your browser:

[http://127.0.0.1:5000](http://127.0.0.1:5000)

Register an account, log in, and use dummy information to explore the application.

## Running Tests

Run the test suite from the project root:

```powershell
python -m unittest discover -s tests -v
```

The tests cover cryptographic operations, envelope validation, integrity verification, file payload handling, and selected application behaviors.

## Project Structure

```text
InformationSecurity_Task-1_Group-9/
├── app.py                 # Flask routes and application logic
├── config.py              # Master key configuration
├── crypto_core.py         # AES, DES, RC4, and integrity verification
├── crypto_tool.py         # Standalone cryptography utility
├── db.py                  # SQLite database operations
├── file_payload.py        # File metadata and payload handling
├── storage.py             # Private encrypted file storage
├── templates/             # HTML/Jinja templates
├── static/                # CSS and JavaScript assets
├── tests/                 # Automated tests
├── docs/                  # Project design and cryptography contract
├── requirements.txt       # Python dependencies
└── README.md
```

## Project Scope

Medimo uses a single application role: the record owner. Doctor accounts, administrator roles, and record-sharing links are outside the current scope.

The project focuses on demonstrating secure data handling, cryptographic integrity, ownership checks, and the practical trade-offs between different encryption algorithms.

## Academic Context

This project was developed by **Group 9** for the **Information Security (I)** course.

**Lecturer:** Dr. Baskoro Adi Pratomo, S.Kom., M.Kom., Ph.D.

### Team Members

| No. | Student Name | Student ID |
|---:|---|---|
| 1 | Adelia Tanalina Yumna | 5025241078 |
| 2 | Almira Nayla Felisitha | 5025241014 |
| 3 | Embun Nabila Azzahra Rasendrya | 5025241009 |
| 4 | Nuha Usama Okbah | 5025241005 |

**Repository:** [InformationSecurity_Task-1_Group-9](https://github.com/embunabila/InformationSecurity_Task-1_Group-9)
