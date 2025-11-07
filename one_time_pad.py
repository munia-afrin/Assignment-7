"""
one_time_pad.py
Simple, careful OTP implementation for educational / controlled use.
- Uses os.urandom() for key generation
- Works on bytes (so handles arbitrary binary data)
- Stores ciphertext as base64 for convenience
- Includes metadata handling and basic HMAC authentication (optional)
"""

import os
import base64
import hmac
import hashlib
from typing import Tuple, Optional

# ---------- Utility functions ----------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays (a and b must be same length)."""
    if len(a) != len(b):
        raise ValueError("Lengths must match for OTP XOR.")
    return bytes(x ^ y for x, y in zip(a, b))

# ---------- Key generation & handling ----------

def generate_key(length: int) -> bytes:
    """Generate a cryptographically secure random key of given length (bytes)."""
    if length <= 0:
        raise ValueError("Length must be > 0")
    return os.urandom(length)

def save_key(path: str, key: bytes, mode: int = 0o600) -> None:
    """Save key to a file with restrictive permissions."""
    # Write binary
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, mode)
    except Exception:
        # On some platforms (Windows), chmod may be no-op. That's OK, but warn in docs.
        pass

def load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

# Optional: best-effort secure wipe (overwrite)
def wipe_file(path: str) -> None:
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
    except Exception:
        # If we cannot reliably wipe, just remove file (best-effort).
        try:
            os.remove(path)
        except Exception:
            pass

# ---------- Encryption / Decryption ----------

def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """Return raw ciphertext bytes (same length as plaintext)."""
    if len(key) != len(plaintext):
        raise ValueError("Key length must equal plaintext length for OTP.")
    return xor_bytes(plaintext, key)

def decrypt_bytes(ciphertext: bytes, key: bytes) -> bytes:
    """OTP decryption is the same as encryption."""
    return encrypt_bytes(ciphertext, key)

# Convenience wrappers for text data (UTF-8)
def encrypt_text(plaintext: str, key: bytes) -> str:
    pt_bytes = plaintext.encode("utf-8")
    if len(key) != len(pt_bytes):
        raise ValueError("Key length must equal plaintext byte-length for text OTP.")
    ct = encrypt_bytes(pt_bytes, key)
    return base64.b64encode(ct).decode("ascii")

def decrypt_text(cipher_b64: str, key: bytes) -> str:
    ct = base64.b64decode(cipher_b64)
    pt_bytes = decrypt_bytes(ct, key)
    return pt_bytes.decode("utf-8")

# ---------- Optional HMAC wrapper for ciphertext integrity ----------
# You may want to authenticate stored ciphertext. This does NOT replace OTP.
def auth_ciphertext(ciphertext: bytes, auth_key: bytes) -> bytes:
    """Return ciphertext || HMAC where HMAC uses auth_key."""
    h = hmac.new(auth_key, ciphertext, hashlib.sha256).digest()
    return ciphertext + h

def verify_and_strip_auth(data_with_hmac: bytes, auth_key: bytes) -> bytes:
    """Verify HMAC and return ciphertext, raise if invalid."""
    if len(data_with_hmac) < 32:
        raise ValueError("Data too short for HMAC.")
    ciphertext = data_with_hmac[:-32]
    mac = data_with_hmac[-32:]
    expected = hmac.new(auth_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("HMAC verification failed.")
    return ciphertext

# ---------- Example usage ----------
if __name__ == "__main__":
    # Example text encryption
    message = "Hello, Munia! This is a secret message."
    pt = message.encode("utf-8")
    key = generate_key(len(pt))
    ciphertext = encrypt_bytes(pt, key)
    print("Ciphertext (base64):", base64.b64encode(ciphertext).decode("ascii"))

    # Decrypt
    recovered = decrypt_bytes(ciphertext, key)
    print("Recovered:", recovered.decode("utf-8"))

    # Save key and wipe after use (example)
    keyfile = "secret.key"
    save_key(keyfile, key)
    # After you used the key once and are done: wipe_file(keyfile)

