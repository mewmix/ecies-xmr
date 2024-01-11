import os
from ed25519 import * 
from Crypto.Cipher import AES

def generate_monero_keypair():
    private_spend_key = os.urandom(32)
    private_view_key = H(private_spend_key)[:32]  # Derive view key from spend key
    public_spend_key = publickey(private_spend_key)
    public_view_key = publickey(private_view_key)
    return (private_spend_key, public_spend_key), (private_view_key, public_view_key)

def encrypt(sender_private_spend_key, receiver_public_view_key, message):
    if isinstance(message, str):
        message = message.encode()

    shared_secret = scalarmult(decodepoint(receiver_public_view_key), decodeint(sender_private_spend_key))
    key = H(encodepoint(shared_secret))[:32]

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    print("Encryption - Key:", key.hex())
    print("Encryption - Nonce:", cipher.nonce.hex())

    return ciphertext, tag, cipher.nonce

def decrypt(receiver_private_view_key, sender_public_spend_key, ciphertext, tag, nonce):
    try:
        shared_secret = scalarmult(decodepoint(sender_public_spend_key), decodeint(receiver_private_view_key))
        key = H(encodepoint(shared_secret))[:32]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        print("Decryption - Key:", key.hex())
        print("Decryption - Nonce:", nonce.hex())

        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# Generate key pairs for sender and receiver
sender_keys, _ = generate_monero_keypair()
_, receiver_keys = generate_monero_keypair()

# Testing with a message
original_message = "Hello, this is a test message!"

# Encrypt the message using sender's private spend key and receiver's public view key
ciphertext, tag, nonce = encrypt(sender_keys[0], receiver_keys[1], original_message)
print(sender_keys[0].hex())
print(receiver_keys[0].hex())
# Decrypt the message using receiver's private view key and sender's public spend key
decrypted_message = decrypt(receiver_keys[0], sender_keys[1], ciphertext, tag, nonce)

# Check if the decryption is successful and matches the original message
if decrypted_message:
    decrypted_message = decrypted_message.decode()
    print(f"Decrypted Message: {decrypted_message}")
    assert decrypted_message == original_message, "Decryption failed or message corrupted!"
else:
    print("Decryption failed.")



 