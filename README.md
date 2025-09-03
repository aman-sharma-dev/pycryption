# 🔐 PyCryption

A powerful **file, text, and folder encryption tool** with a **Flask-powered web UI**, a **Python GUI**, and a **command-line interface (CLI)**.
Supports key management, password-based encryption, and multiple encryption methods.

![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/flask-2.x-lightgrey?logo=flask)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
<!-- Uncomment these when available
![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)
![PyPI](https://img.shields.io/pypi/v/pycryption)
-->
---

## 📂 Project Structure

<details>
<summary>Click to expand</summary>

```
.
├── app
│   ├── web_ui
│   │   ├── templates
│   │   │   ├── base.html
│   │   │   ├── file_encryption.html
│   │   │   ├── index.html
│   │   │   └── text_encryption.html
│   │   ├── __init__.py
│   │   ├── forms.py
│   │   └── routes.py
│   ├── __init__.py
│   ├── cli.py
│   └── crypto_utils.py
├── assets
│   └── favicon.ico
├── instance
├── tests
│   └── tests.py
├── .env
├── .env.example
├── .gitignore
├── config.py
├── devserver.sh
├── Dockerfile
├── gui.py
├── main.py
├── PyCryption.spec
├── README.md
├── requirements.txt
├── run.py
└── wsgi.py
```
</details>

---

## ⚡ Features

- 🔑 **Key Management**: persistent keys, load/save keys, password-based keys
- 📝 **Text Encryption/Decryption**: available in GUI, CLI, Web UI
- 📂 **File & Folder Encryption/Decryption**: using Fernet keys or passwords
- 🌐 **Flask Web UI**: browser-based, user-friendly interface
- 🖥 **Tkinter-based GUI App** for non-technical users
- 🛠 **CLI Tools** for developers and scripting
- 🔒 **Demo Ciphers** (Caesar Cipher and more)

---

## 🚀 Getting Started

### 1. Environment Setup

Create and activate a Python virtual environment:

```
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows
```

**Install dependencies:**

```
pip install -r requirements.txt
```

---

### 2. Running the Web Application

**Development server:**
```
./devserver.sh
```

**Production (Gunicorn):**
```
gunicorn --bind 0.0.0.0:8080 wsgi:app
```

---

### 3. Running the GUI

```
python gui.py
```

**Main Features:**
- Generate & manage encryption keys
- Encrypt/Decrypt text
- Encrypt/Decrypt files
- Persistent key storage

---

### 4. Command-Line Interface (CLI)

Activate your venv, then use:

```
flask encryptor --help
```

#### 🔑 Key Management

```
# Generate random key → secret.key
flask encryptor generate-key

# Derive key from password
flask encryptor generate-key --from-password "my_strong_password"
```

#### 📝 Text Encryption/Decryption

```
flask encryptor encrypt-text "My secret message"
flask encryptor decrypt-text "gAAAAABl..."

# Supports --key or --password overrides
```

#### 📂 File Encryption/Decryption

```
flask encryptor encrypt-file path/to/file.txt
flask encryptor decrypt-file path/to/file.txt.enc
```

#### 📁 Folder Encryption/Decryption

```
flask encryptor encrypt-folder path/to/folder --password "mypassword"
flask encryptor decrypt-folder path/to/encrypted_folder --password "mypassword"
```

#### 🔡 Caesar Cipher (Demo)

```
flask encryptor caesar "Hello World" 3
```

---

### 5. Running Tests

```
pytest
```

---

### 6. Building Executables (PyInstaller)

Create a standalone executable:
```
pyinstaller --onefile --windowed --add-data "assets;assets" gui.py
```
Executable will be in the `dist/` folder.

---

## ⚙️ Configuration

- `config.py`: application defaults
- `instance/config.py`: environment-specific (ignored in git)

Switch environment:
```
export FLASK_CONFIG=production
```

---

## 📌 Roadmap

- [ ] AES/GCM encryption support
- [ ] Cloud key vault integration
- [ ] Docker deployment examples
- [ ] WebSocket-based live encryption demo

---

## 🤝 Contributing

- **Fork** the project
- Create your feature branch: `git checkout -b feature/amazing-feature`
- **Commit** your changes: `git commit -m 'Add amazing feature'`
- **Push** to the branch: `git push origin feature/amazing-feature`
- **Open a Pull Request**

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

---

## ✨ Acknowledgements

- Flask
- PyInstaller
- cryptography

---