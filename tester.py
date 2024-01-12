import binascii
from bip_utils import Monero, MoneroMnemonicGenerator, MoneroSeedGenerator, MoneroWordsNum
from ecies_xmr import MoneroECIES

def generate_monero_keys():
    mnemonic = MoneroMnemonicGenerator().FromWordsNumber(MoneroWordsNum.WORDS_NUM_25)
    print(f"Mnemonic string: {mnemonic}")
    seed_bytes = MoneroSeedGenerator(mnemonic).Generate()
    monero = Monero.FromSeed(seed_bytes)

    # Generate keys using bip_utils
    private_spend_key_bip_utils = monero.PrivateSpendKey().Raw()
    private_view_key_bip_utils = monero.PrivateViewKey().Raw()
    public_spend_key_bip_utils = monero.PublicSpendKey().RawCompressed()
    public_view_key_bip_utils = monero.PublicViewKey().RawCompressed()
    print(private_spend_key_bip_utils)
    print(private_view_key_bip_utils)
    print(public_spend_key_bip_utils)
    print(public_view_key_bip_utils)
    return (
        private_spend_key_bip_utils, public_spend_key_bip_utils,
        private_view_key_bip_utils, public_view_key_bip_utils
    )

# Generate keys for Alice
alice_private_spend_key, alice_public_spend_key, alice_private_view_key, alice_public_view_key = generate_monero_keys()

# Generate keys for Bob
bob_private_spend_key, bob_public_spend_key, bob_private_view_key, bob_public_view_key = generate_monero_keys()


# Encrypt and decrypt the message
message = "Hello, Bob! This is Alice."
ciphertext, tag, nonce = MoneroECIES.encrypt(alice_private_spend_key, bob_public_view_key, message)
decrypted_message = MoneroECIES.decrypt(bob_private_view_key, alice_public_spend_key, ciphertext, tag, nonce)

# Print results
print("\nTesting Encryption and Decryption:")
print(f"Original message: {message}")
print(f"Encrypted message: {binascii.hexlify(ciphertext)}")
print(f"Decrypted message: {decrypted_message.decode()}")
