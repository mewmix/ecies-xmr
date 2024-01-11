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
original_message2 = "Hello, this is a new test message!"
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



import binascii

def hex_to_bytes(hex_string):
    return binascii.unhexlify(hex_string)

# Provided keys
secret_spend_key_hex = "3f1268445c91485748e0a1130591cf6b821c4f71f2ed332e39c84bcdf5df2507"
secret_view_key_hex = "a0c496e2cb98e552eb00c817621a5e1f8d87abc780f1b7bf55b5772100f98b0f"

# Convert hex keys to bytes
secret_spend_key = hex_to_bytes(secret_spend_key_hex)
secret_view_key = hex_to_bytes(secret_view_key_hex)

# Generate public keys
public_spend_key = publickey(secret_spend_key)
public_view_key = publickey(secret_view_key)

# Now you can use these keys with your encrypt and decrypt functions
# ...

# Run encryption
ciphertext, tag, nonce = encrypt(secret_spend_key, public_view_key, original_message2)

# Run decryption
decrypted_message2 = decrypt(secret_view_key, public_spend_key, ciphertext, tag, nonce)
print(decrypted_message2)
# Check decryption result
# ...
