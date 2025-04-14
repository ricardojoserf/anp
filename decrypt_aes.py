import sys
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

password = b"TEST1234"
key = hashlib.sha256(password).digest()

encrypted_b64 = sys.argv[1]

# Step 1: Decode Base64
ciphertext = base64.b64decode(encrypted_b64)

# Step 2: AES CBC mode decryption with 0 IV (CryptoAPI default behavior)
iv = b"\x00" * 16
cipher = AES.new(key, AES.MODE_CBC, iv)

# Step 3: Decrypt and unpad
try:
    decrypted = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted, AES.block_size).decode('utf-8')
    print(plaintext)
except Exception as e:
    print("Decryption failed:", str(e))