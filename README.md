<div align="center">

# 🔑 XORKey 🔑

**A versatile Python tool for symmetric encryption using XOR operations, featuring multiple encryption modes, customizable keys, and various output formats.**

</div>

---

## 📖 Table of Contents

- [✨ Key Features](#-key-meatures)
- [⚙️ How It Works](#️-how-it-works)
- [💾 Installation](#-installation)
- [🚀 Usage](#-usage)
- [📁 Project Structure](#-project-structure)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---
## > [!NOTE]
> This is a beginner project and is probably not up to standard and the code may be badly structured; I tried my best with minimal A.I usage(except this readme lol)
## ✨ Key Features

- **🔒 Core XOR Encryption/Decryption:** Implements the fundamental XOR cipher for fast and secure data encryption.
- **🔑 Multiple Encryption Modes:**
    - **OTP (One-Time Pad):** Generates a random, secure password for each encryption, providing the highest level of security.
    - **Personal:** Allows you to use your own password for encryption, combined with a salt and PBKDF2 for enhanced security.
    - **Pure:** A raw binary mode for special use cases.
- ** Automatic Format Detection:** Can automatically detect the encryption format during decryption.
- ** Multiple Output Formats:** Supports Base64 and raw binary output.
- ** Command-Line Interface:** A user-mriendly CLI for easy encryption and decryption directly from your terminal.
- ** Modular Design:** The project is structured into logical modules, making it easy to understand, maintain, and extend.

---

## ⚙️ How It Works

XORKey encrypts data by XORing it with a generated keystream. The way the keystream is generated depends on the chosen encryption mode:

- **OTP Mode:** A cryptographically secure random password is generated for each encryption. This password, combined with the encrypted message, forms a one-time pad. This is the most secure mode.(Well not yet, authenthencitity verification has not been implemented yet)
- **Personal Mode:** A user-provided password is used to derive a secure key using PBKDF2 with a random salt. This method is also very secure and allows you to use a memorable password.

The CLI (`xorkey.main`) provides a simple interface to these encryption methods, handling input/output and formatting.

---

## 💾 Installation

You can install XORKey in two ways, depending on your needs.

### For Users (Recommended)

This method is for users who want to use XORKey as a command-line tool. It uses `pipx` to install the package in an isolated environment.

```bash
pipx install git+https://github.com/DevTheCoder-py/XorKey/
```

### For Developers

This method is for developers who want to contribute to the project or modify the code.

```bash
# Clone the repository
git clone https://github.com/DevTheCoder-py/XorKey.git
cd XorKey

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package in editable mode
pip install -e .
#or use pipx if preferred
```

---

## 🚀 Usage

XORKey can be used directly from the command line.

### Encrypting Data

**Using OTP Mode (Default):**

```bash
xorkey -e "My secret message"
```

This will output the Base64 encoded encrypted message and the randomly generated password.

**Using Personal Mode:**

```bash
xorkey -e "My secret message" -m personal
```

You will be prompted to enter a password for encryption.

### Decrypting Data

**Using Auto-Detect Mode (Default):**

```bash
xorkey -d "<ENCRYPTED_MESSAGE>"
```

The tool will try to automatically detect the encryption format. You will be prompted for the password if necessary.

**Specifying the Mode:**

If auto-detection fails, you can specify the mode manually.

```bash
# For OTP mode
xorkey -d "<ENCRYPTED_MESSAGE>" -m OTP

# For Personal mode
xorkey -d "<ENCRYPTED_MESSAGE>" -m personal
```

You will be prompted for the password.

### Encrypting/Decrypting Files

XORKey can also encrypt or decrypt the content of a file.

**Encrypting a File:**

To encrypt the content of `my_secret.txt` and save it to `encrypted.txt`:
```bash
xorkey -e -f my_secret.txt -o encrypted.txt
```

This command reads the content of `my_secret.txt`, encrypts it, and writes the encrypted output to `encrypted.txt`. 
If you are using `OTP` or `pure` mode, a password file named `encrypted.pass` will be created in the same directory.

**Decrypting a File:**

To decrypt the content of `encrypted.txt` and save it to `decrypted.txt`:
```bash
xorkey -d -f encrypted.txt -o decrypted.txt
```

This command reads the content of `encrypted.txt` and decrypts it. If the file was encrypted in `OTP` or `pure` mode, it will automatically look for the password in `encrypted.pass`. If you used `personal` mode, you will be prompted for your password.

---

## 📁 Project Structure

- **`xorkey/core.py`**: Contains the core logic for encryption and decryption.
- **`xorkey/main.py`**: Implements the command-line interface.
- **`xorkey/utils.py`**: Provides utility functions for string manipulation, encoding, and more.
- **`tests/`**: Contains unit tests or trials for the project.

---

## 🤝 Contributing

Contributions are welcome! If you have any ideas, suggestions, or bug reports, please open an issue or submit a pull request.
After all, this is simply a beginner project that I wanted to try making. 
---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
