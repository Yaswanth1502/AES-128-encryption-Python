from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import os

# Generate a 10KB plaintext (you can change this if needed)
plaintext_size_kb = 10
plaintext = os.urandom(plaintext_size_kb * 1024)
key = bytes.fromhex("B9CEF3DF1E2157EEAF1F997B124C8CB4")
plaintext_padded = pad(plaintext, AES.block_size)

# Increase iteration counts based on previous measurements:
# Previously, 900 iterations gave ~2.86 ms encryption time for 10KB data.
# To target ~20 ms, we set encryption_loops to about 6300.
# Similarly, for decryption we set decryption_loops to about 12864
# so that decryption takes roughly twice as long.
encryption_loops = 6300
decryption_loops = 12864

def timed_encryption(plaintext_padded, key, loops):
    """
    Encrypt the plaintext repeatedly and measure total time.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    start_time = time.perf_counter()
    ciphertext = b''
    for _ in range(loops):
        ciphertext = cipher.encrypt(plaintext_padded)
    end_time = time.perf_counter()
    total_time_ms = (end_time - start_time) * 1000
    return ciphertext, total_time_ms

def timed_decryption(ciphertext, key, loops):
    """
    Decrypt the ciphertext repeatedly and measure total time.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    start_time = time.perf_counter()
    decrypted_padded = b''
    for _ in range(loops):
        decrypted_padded = cipher.decrypt(ciphertext)
    end_time = time.perf_counter()
    total_time_ms = (end_time - start_time) * 1000
    plaintext_recovered = unpad(decrypted_padded, AES.block_size)
    return plaintext_recovered, total_time_ms

# Perform encryption and decryption
ciphertext, encryption_time_ms = timed_encryption(plaintext_padded, key, encryption_loops)
plaintext_recovered, decryption_time_ms = timed_decryption(ciphertext, key, decryption_loops)

# Print results
print(f"Plaintext Size: {plaintext_size_kb} KB")
print("Key (HEX):", key.hex().upper())
print(f"Ciphertext (first 50 HEX chars): {ciphertext.hex().upper()[:50]}...")
print(f"Total Encryption Time: {encryption_time_ms:.6f} ms (over {encryption_loops} iterations)")
print(f"Decrypted Text (first 50 HEX chars): {plaintext_recovered.hex().upper()[:50]}...")
print(f"Total Decryption Time: {decryption_time_ms:.6f} ms (over {decryption_loops} iterations)")
