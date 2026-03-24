# XORKey

A command-line tool for symmetric encryption using XOR operations. Supports multiple encryption modes and file I/O.

> Beginner project. Not audited for production use. Avoid using `ast.literal_eval()` in server environments.

---

## Installation

**As a CLI tool (recommended):**
```bash
pipx install git+https://github.com/DevTheCoder-py/XorKey/
```

**For development:**
```bash
git clone https://github.com/DevTheCoder-py/XorKey.git
cd XorKey
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Modes

| Mode | Description |
|------|-------------|
| `personal` | Derives a key from your password using PBKDF2 + random salt. Default for encryption. |
| `OTP` | Generates a random password per encryption. Output is Base64 encoded. |
| `pure` | Raw binary variant of OTP. No encoding or authentication features. |
| `auto` | Attempts to detect the mode automatically during decryption. Default for decryption. |

---

## Usage

### Encrypt

```bash
# Personal mode (default) — prompts for password
xorkey -e "message"

# OTP mode — generates a random password
xorkey -e "message" -m OTP
```

### Decrypt

```bash
# Auto-detect mode (default)
xorkey -d "<ciphertext>"

# Specify mode manually
xorkey -d "<ciphertext>" -m personal
xorkey -d "<ciphertext>" -m OTP
```

### Files

```bash
# Encrypt a file
xorkey -e -f input.txt -o encrypted.txt

# Decrypt a file
xorkey -d -f encrypted.txt -o decrypted.txt
```

When encrypting a file with OTP or pure mode, a `<filename>.pass` file is created alongside the output. Decryption will look for this file automatically.

---

## Arguments

```
-e, --encrypt [TEXT]      Encrypt text or file content
-d, --decrypt [CIPHER]    Decrypt ciphertext or file content
-m, --mode MODE           Encryption mode: pure | OTP | personal | auto
-f, --file FILE           Input file
-o, --output FILE         Output file
```

---

## How It Works

- **OTP:** A cryptographically secure random password is generated and XORed against the input as a keystream.
- **Personal:** Your password is run through PBKDF2 with a random salt to derive the keystream.
- **Pure:** Same as OTP without Base64 encoding or authentication overhead.

---

## Project Structure

```
xorkey/
  core.py    # Encryption and decryption logic
  main.py    # CLI
  utils.py   # Encoding and helper functions
tests/       # Tests
```

---

## License

MIT. See [LICENSE](LICENSE).
