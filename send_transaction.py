import json, time, requests
from ecdsa import SigningKey, SECP256k1

# ===================== CONFIGURATION =====================
PRIVATE_KEY_HEX = "PUT_YOUR_PRIVATE_KEY_HERE"
SENDER_NAME = "Alice"
RECIPIENT_NAME = "Bob"
AMOUNT = 25
NODE_URL = "http://localhost:5000/transactions/new"
# ==========================================================


def create_signed_transaction(sender, recipient, amount, priv_hex):
    priv_key = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1)
    tx = {"sender": sender, "recipient": recipient, "amount": amount, "timestamp": time.time()}
    tx_string = json.dumps(tx, sort_keys=True)
    signature = priv_key.sign(tx_string.encode()).hex()
    pubkey = priv_key.get_verifying_key().to_string().hex()
    tx.update({"signature": signature, "pubkey": pubkey})
    return tx


def send_transaction(transaction):
    headers = {"Content-Type": "application/json"}
    r = requests.post(NODE_URL, data=json.dumps(transaction), headers=headers)
    print(f"Status {r.status_code}")
    print(r.text)


if __name__ == "__main__":
    if PRIVATE_KEY_HEX == "PUT_YOUR_PRIVATE_KEY_HERE":
        from ecdsa import SigningKey, SECP256k1
        sk = SigningKey.generate(curve=SECP256k1)
        print("⚠️  No key found — generated a new one!")
        print("Private:", sk.to_string().hex())
        print("Public :", sk.get_verifying_key().to_string().hex())
        print("Copy your private key above into PRIVATE_KEY_HEX and run again.")
        exit()

    tx = create_signed_transaction(SENDER_NAME, RECIPIENT_NAME, AMOUNT, PRIVATE_KEY_HEX)
    print("🚀 Sending signed transaction...")
    send_transaction(tx)
