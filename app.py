# mini_blockchain/app.py
import sys
import json
import time
import requests
from flask import Flask, request, jsonify, render_template, render_template_string
from blockchain import SimpleDB, Blockchain, generate_keys, sign_transaction_dict, verifying_key_to_hex, signing_key_to_hex

app = Flask(__name__, template_folder='templates', static_folder='static')
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
NODE_ID = f"Node{PORT}"
BASE_URL = f"http://localhost:{PORT}"

# storage and blockchain
db = SimpleDB()
bc = Blockchain(db, difficulty=3)

# simple template (you can replace with your earlier HTML_TEMPLATE or keep it here)
INDEX_HTML = open("templates/index.html", encoding="utf-8").read()


@app.route('/')
def index():
    return render_template_string(INDEX_HTML, node_id=NODE_ID, port=PORT)

# ----- transactions -----
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError

def verify_transaction(transaction, signature, pubkey_hex):
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(pubkey_hex), curve=SECP256k1)
        tx_copy = transaction.copy()
        tx_copy.pop("signature", None)
        tx_copy.pop("pubkey", None)
        tx_str = json.dumps(tx_copy, sort_keys=True)
        return vk.verify(bytes.fromhex(signature), tx_str.encode())
    except (BadSignatureError, Exception):
        return False


@app.route("/transactions/new", methods=["POST"])
def new_transaction():
    values = request.get_json()
    required = ["sender", "recipient", "amount", "signature", "pubkey"]

    if not all(k in values for k in required):
        return jsonify({"error": "Signature and pubkey required for non-network transactions"}), 400

    # Verify the signature (skip for network rewards)
    if values["sender"] != "network":
        if not verify_transaction(values, values["signature"], values["pubkey"]):
            return jsonify({"error": "Invalid signature"}), 400

    tx = {
        "sender": values["sender"],
        "recipient": values["recipient"],
        "amount": values["amount"],
        "timestamp": time.time(),
    }
    blockchain.add_transaction(tx)
    return jsonify({"message": "Transaction added!", "transaction": tx}), 201

# ----- mining -----
@app.route('/mine', methods=['GET'])
def mine():
    miner = request.args.get('miner', 'miner1')
    res = bc.mine_block(miner)
    if not res:
        return jsonify({'message': 'Aucune transaction à miner !'}), 400
    block, mining_time = res
    # broadcast newly mined block to peers (best-effort)
    for peer in db.list_nodes():
        try:
            requests.post(f"{peer}/receive_block", json=block.to_dict(), timeout=1)
        except:
            pass
    return jsonify({'message': f'Bloc #{block.index} miné en {mining_time:.2f}s', 'block': block.to_dict()}), 200

# receive a block broadcasted by another node
@app.route('/receive_block', methods=['POST'])
def receive_block():
    block_data = request.get_json()
    # naive append if previous hash matches and block valid
    last = bc.chain[-1]
    if block_data['previous_hash'] == last.hash:
        # create Block and verify PoW
        from blockchain import Block
        b = Block(block_data['index'], block_data['transactions'], block_data['previous_hash'],
                  timestamp=block_data['timestamp'], nonce=block_data['nonce'], merkle_root=block_data.get('merkle_root'),
                  hash=block_data.get('hash'))
        if b.hash.startswith('0' * bc.difficulty) and b.hash == b.compute_hash():
            bc.chain.append(b)
            bc.persist_block(b)
            # remove included txs from mempool
            txids = [tx['txid'] for tx in b.transactions if tx.get('sender') != 'network']
            bc.remove_mempool_txs(txids)
            return jsonify({'message': 'Bloc accepté'}), 201
    return jsonify({'message': 'Bloc rejeté'}), 400

# ----- chain and validate -----
@app.route('/chain', methods=['GET'])
def full_chain():
    chain = [b.to_dict() for b in bc.chain]
    return jsonify({'length': len(chain), 'chain': chain, 'pending_transactions': bc.mempool, 'difficulty': bc.difficulty}), 200

@app.route('/validate', methods=['GET'])
def validate():
    valid = bc.is_chain_valid()
    return jsonify({'valid': valid, 'message': 'La blockchain est valide' if valid else 'Chaîne invalide'}), 200

# ----- balance -----
@app.route('/balance/<address>', methods=['GET'])
def balance(address):
    return jsonify({'address': address, 'balance': bc.get_balance(address)}), 200

# ----- node registration & consensus -----
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes', [])
    if not nodes:
        return jsonify({'error': 'No nodes provided'}), 400
    for n in nodes:
        db.add_node(n)
    return jsonify({'message': 'Nœuds enregistrés', 'total_nodes': db.list_nodes()}), 201

@app.route('/nodes', methods=['GET'])
def list_nodes():
    return jsonify({'nodes': db.list_nodes()}), 200

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = False
    max_len = len(bc.chain)
    best_chain = None
    for node in db.list_nodes():
        try:
            r = requests.get(f"{node}/chain", timeout=2)
            if r.status_code == 200:
                data = r.json()
                length = data['length']
                chain_data = data['chain']
                # check validity locally using temp blockchain object
                if length > max_len:
                    # we attempt to validate with our blockchain.verify method
                    if bc.replace_chain(chain_data):
                        replaced = True
                        max_len = length
        except Exception as e:
            pass
    if replaced:
        return jsonify({'message': 'Notre chaîne a été remplacée'}), 200
    return jsonify({'message': 'Notre chaîne est la plus longue'}), 200

# ----- utility to add node from UI -----
@app.route('/nodes/add', methods=['POST'])
def add_node_ui():
    v = request.get_json()
    url = v.get('url')
    if not url:
        return jsonify({'error': 'url manquante'}), 400
    db.add_node(url)
    return jsonify({'message': 'Nœud ajouté', 'nodes': db.list_nodes()}), 201
# ---- ROUTE POUR CHANGER DIFFICULTE ----
@app.route('/difficulty/set', methods=['POST'])
def set_difficulty():
    v = request.get_json().get('difficulty')
    try:
        v = int(v)
        if v < 1:
            return jsonify({'error': 'Valeur invalide'}), 400
        bc.difficulty = v
        bc.db.set_meta('difficulty', v)
        return jsonify({'message': f'Difficulté mise à {v}'}), 200
    except:
        return jsonify({'error': 'Format incorrect'}), 400

# ---- ROUTE POUR STATS GRAPHIQUE ----
@app.route('/stats', methods=['GET'])
def stats():
    blocks = [b.index for b in bc.chain]
    times = []
    for i in range(1, len(bc.chain)):
        t = bc.chain[i].timestamp - bc.chain[i-1].timestamp
        times.append(round(t, 2))
    return jsonify({'blocks': blocks[1:], 'times': times, 'difficulty': bc.difficulty})

if __name__ == "__main__":
    print(f"🚀 Démarrage {NODE_ID} sur {BASE_URL}")
    app.run(host='0.0.0.0', port=PORT, debug=False)

