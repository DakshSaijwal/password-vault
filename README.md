# Password Vault (v1.0)

A local, offline, encrypted password manager written in Python.

This project is designed to store website/app credentials securely on disk using modern cryptography, without any cloud sync or external services.

---

## Features

- 🔐 Master-password–protected vault
- 🧠 Strong key derivation (Argon2)
- 🔒 Authenticated encryption (AES-GCM)
- 📦 Local SQLite database (`vault.db`)
- ✏️ Full CRUD support (add, view, edit, delete entries)
- 🔍 Fuzzy search for sites
- 📋 Secure clipboard copy with auto-clear
- 📊 Password entropy detection and warnings
- 🔄 Master password rotation
- 📤 Export / import encrypted entries
- 🧪 Test-backed core logic

---

## Security Model

- All passwords are encrypted before being written to disk
- The master password is **never stored**
- A verification value encrypted with the master key is used to validate correctness
- If the master password is lost, **data is unrecoverable**
- Clipboard contents are automatically cleared after a timeout and on exit

This vault is intended for **local, single-user use**.

---

## Project Structure
```
password_vault/
├── main.py              ## CLI interface
├── vault_class.py       ## Core Vault implementation
├── crypto.py            ## Cryptographic primitives
├── tests/               ## Pytest-based test suite
├── .gitignore           ## Version control exclusions
└── README.md            ## Project documentation
```

---

## Requirements

- Python 3.10+
- Required packages:
  - `cryptography`
  - `argon2-cffi`
  - `pyperclip`
  - `pytest` (for tests)

Install dependencies:

```bash
pip install cryptography argon2-cffi pyperclip pytest
```
## Usage

Run the vault:

```bash
python main.py
```

You will be prompted for a master password:

If the vault does not exist, it will be created

If it exists, the password must be correct to unlock it

Follow the on-screen menu to manage entries.

The encrypted database file is:

```bash
vault.db
```
You are responsible for backing it up.

## Recommended:

Keep at least one offline backup

Test restoring from backup at least once
```
⚠️ Do not commit vault.db to version control.
```
## Testing

Run the full test suite:

```bash
python -m pytest
```
All core functionality is covered by tests.


## Threat Model (Explicit)

This project does not protect against:

- Malware with access to your running system

- Keyloggers

- A compromised OS

- Physical access while the vault is unlocked

It does protect against:

- Casual file access

- Disk theft

- Accidental plaintext exposure

## Project Status
```bash
 – v1.0
```
```
Intended as a stable, personal tool
```
#### cheers
---
