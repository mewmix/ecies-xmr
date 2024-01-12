import binascii
from ecies_xmr import MoneroECIES
from bip_utils import Monero, MoneroMnemonicGenerator, MoneroSeedGenerator, MoneroWordsNum
from ecies_xmr.ed25519 import publickey

def generate_monero_keys():
    mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
    print(f"Mnemonic string: {mnemonic}")
    seed_bytes = MoneroSeedGenerator(mnemonic).Generate()
    monero = Monero.FromSeed(seed_bytes)

    private_spend_key_hex = monero.PrivateSpendKey().Raw().ToHex()
    private_view_key_hex = monero.PrivateViewKey().Raw().ToHex()

    private_spend_key = MoneroECIES.hex_to_bytes(private_spend_key_hex)
    private_view_key = MoneroECIES.hex_to_bytes(private_view_key_hex)

    # Generate public keys using ed25519
    public_spend_key_ed25519 = publickey(private_spend_key)
    public_view_key_ed25519 = publickey(private_view_key)

    # Get public keys from bip_utils
    public_spend_key_bip_utils = monero.PublicSpendKey().RawCompressed().ToBytes()
    public_view_key_bip_utils = monero.PublicViewKey().RawCompressed().ToBytes()

    return {
        "private_spend_key": private_spend_key,
        "private_view_key": private_view_key,
        "public_spend_key_ed25519": public_spend_key_ed25519,
        "public_view_key_ed25519": public_view_key_ed25519,
        "public_spend_key_bip_utils": public_spend_key_bip_utils,
        "public_view_key_bip_utils": public_view_key_bip_utils
    }

def test_encryption_decryption(sender_keys, receiver_keys):
    message = "Hello, Bob! This is Alice."
    ciphertext, tag, nonce = MoneroECIES.encrypt(sender_keys["private_spend_key"], receiver_keys["public_view_key_ed25519"], message)
    decrypted_message = MoneroECIES.decrypt(receiver_keys["private_view_key"], sender_keys["public_spend_key_ed25519"], ciphertext, tag, nonce)
    
    print("\nTesting Encryption and Decryption:")
    print(f"Original message: {message}")
    print(f"Encrypted message: {binascii.hexlify(ciphertext)}")
    print(f"Decrypted message: {decrypted_message.decode()}")

# Generate keys for Alice and Bob
alice_keys = generate_monero_keys()
bob_keys = generate_monero_keys()

# Test with ed25519 keys
print("\nTesting with ed25519 keys:")
test_encryption_decryption(alice_keys, bob_keys)

# Test with bip_utils keys (replace ed25519 keys with bip_utils keys in the test function)
alice_keys["public_spend_key_ed25519"] = alice_keys["public_spend_key_bip_utils"]
alice_keys["public_view_key_ed25519"] = alice_keys["public_view_key_bip_utils"]
bob_keys["public_spend_key_ed25519"] = bob_keys["public_spend_key_bip_utils"]
bob_keys["public_view_key_ed25519"] = bob_keys["public_view_key_bip_utils"]

print("\nTesting with bip_utils keys:")
test_encryption_decryption(alice_keys, bob_keys)
