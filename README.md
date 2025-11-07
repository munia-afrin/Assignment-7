# One-Time Pad (OTP) Encryption in Python

### 🔐 Overview
This project implements a simple, secure One-Time Pad encryption system in Python using `os.urandom()` for key generation.

### 🚀 How It Works
1. Generate a random key (equal to message length).
2. XOR plaintext bytes with the key.
3. Use Base64 for safe text transfer.
4. Decrypt using the same key.

### 🧠 Features
- True random key (os.urandom)
- File-safe Base64 output
- HMAC option for message authentication
- Secure key wiping

### 🖥 Example
```bash
python one_time_pad.py

