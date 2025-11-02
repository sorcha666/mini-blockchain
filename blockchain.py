# mini_blockchain/blockchain.py
import time
import json
import hashlib
import sqlite3
from ecdsa import VerifyingKey, SigningKey, SECP256k1

DB_FILE = "blockchain.db"
DIFFICULTY_ADJUST_INTERVAL = 5        # every N blocks adjust difficulty
TARGET_BLOCK_TIME = 5.0               # seconds target per block (for demo)

def sha256(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()

def hash_bytes(data: bytes):
    return hashlib.sha256(data).hexdigest()

def current_time():
    return time.time()

class Block:
    def __init__(self, index, transactions, previous_hash, timestamp=None, nonce=0, merkle_root=None, hash=None):
        self.index = index
        self.transactions = transactions  # list of tx dicts
        self.previous_hash = previous_hash
        self.timestamp = timestamp or current_time()
        self.nonce = nonce
        self.merkle_root = merkle_root or self.compute_merkle_root(transactions)
        self.hash = hash or self.compute_hash()

    def to_dict(self):
        return {
            "index": self.index,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "merkle_root": self.merkle_root,
            "hash": self.hash
        }

    def compute_hash(self):
        block_data = {
            'index': self.index,
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'nonce': self.nonce,
            'merkle_root': self.merkle_root
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

    def compute_merkle_root(self, transactions):
        if not transactions:
            return None
        hashes = [hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest() for tx in transactions]
        while len(hashes) > 1:
            temp = []
            for i in range(0, len(hashes), 2):
                a = hashes[i]
                b = hashes[i+1] if i+1 < len(hashes) else hashes[i]
                temp.append(hashlib.sha256((a + b).encode()).hexdigest())
            hashes = temp
        return hashes[0]

class SimpleDB:
    """Tiny sqlite wrapper for storing chain, mempool and nodes."""
    def __init__(self, db_file=DB_FILE):
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self._create_tables()

    def _create_tables(self):
        cur = self.conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS blocks
                       (idx INTEGER PRIMARY KEY, data TEXT)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS mempool
                       (txid TEXT PRIMARY KEY, data TEXT)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS nodes
                       (url TEXT PRIMARY KEY)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS meta
                       (k TEXT PRIMARY KEY, v TEXT)''')
        self.conn.commit()

    # blocks
    def save_block(self, block: Block):
        cur = self.conn.cursor()
        cur.execute('INSERT OR REPLACE INTO blocks (idx, data) VALUES (?, ?)', (block.index, json.dumps(block.to_dict())))
        self.conn.commit()

    def load_blocks(self):
        cur = self.conn.cursor()
        cur.execute('SELECT data FROM blocks ORDER BY idx ASC')
        rows = cur.fetchall()
        out = []
        for (d,) in rows:
            obj = json.loads(d)
            out.append(Block(
                index=obj['index'],
                transactions=obj['transactions'],
                previous_hash=obj['previous_hash'],
                timestamp=obj['timestamp'],
                nonce=obj['nonce'],
                merkle_root=obj.get('merkle_root'),
                hash=obj.get('hash')
            ))
        return out

    # mempool
    def add_tx(self, tx):
        cur = self.conn.cursor()
        cur.execute('INSERT OR REPLACE INTO mempool (txid, data) VALUES (?, ?)', (tx['txid'], json.dumps(tx)))
        self.conn.commit()

    def remove_txs(self, txids):
        cur = self.conn.cursor()
        for txid in txids:
            cur.execute('DELETE FROM mempool WHERE txid = ?', (txid,))
        self.conn.commit()

    def load_mempool(self):
        cur = self.conn.cursor()
        cur.execute('SELECT data FROM mempool')
        return [json.loads(r[0]) for r in cur.fetchall()]

    # nodes
    def add_node(self, url):
        cur = self.conn.cursor()
        cur.execute('INSERT OR IGNORE INTO nodes (url) VALUES (?)', (url,))
        self.conn.commit()

    def remove_node(self, url):
        cur = self.conn.cursor()
        cur.execute('DELETE FROM nodes WHERE url=?', (url,))
        self.conn.commit()

    def list_nodes(self):
        cur = self.conn.cursor()
        cur.execute('SELECT url FROM nodes')
        return [r[0] for r in cur.fetchall()]

    # meta (store difficulty etc.)
    def set_meta(self, k, v):
        cur = self.conn.cursor()
        cur.execute('INSERT OR REPLACE INTO meta (k,v) VALUES (?,?)', (k, json.dumps(v)))
        self.conn.commit()

    def get_meta(self, k, default=None):
        cur = self.conn.cursor()
        cur.execute('SELECT v FROM meta WHERE k=?', (k,))
        row = cur.fetchone()
        if row:
            return json.loads(row[0])
        return default

class Blockchain:
    def __init__(self, db: SimpleDB, difficulty=3):
        self.db = db
        self.difficulty = self.db.get_meta('difficulty', difficulty)
        self.chain = self.db.load_blocks()
        self.mempool = self.db.load_mempool()
        if not self.chain:
            self.create_genesis_block()
        # ensure mempool as list of dicts in memory
        self.mempool = self.db.load_mempool()

    # ---------- persistence helpers ----------
    def persist_block(self, block: Block):
        self.db.save_block(block)
        self.db.set_meta('difficulty', self.difficulty)

    def persist_mempool_tx(self, tx):
        self.db.add_tx(tx)

    def remove_mempool_txs(self, txids):
        self.db.remove_txs(txids)

    # ---------- core ----------
    def create_genesis_block(self):
        initial_transactions = [
            self._create_raw_tx("network", "Alice", 1000),
            self._create_raw_tx("network", "Bob", 1000),
            self._create_raw_tx("network", "Charlie", 1000),
            self._create_raw_tx("network", "miner1", 500),
        ]
        genesis = Block(0, initial_transactions, "0")
        genesis.hash = genesis.compute_hash()
        self.chain = [genesis]
        self.persist_block(genesis)

    def _create_raw_tx(self, sender, recipient, amount, pubkey=None, signature=None):
        tx = {
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "timestamp": current_time(),
            "pubkey": pubkey,
            "signature": signature
        }
        tx['txid'] = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
        return tx

    def create_transaction(self, sender, recipient, amount, pubkey=None, signature=None):
        tx = self._create_raw_tx(sender, recipient, amount, pubkey, signature)
        # verify signature if not network
        if sender != "network":
            if not pubkey or not signature:
                raise ValueError("Signature and pubkey required for non-network transactions")
            if not self.verify_transaction(tx, signature, pubkey):
                raise ValueError("Signature invalid")
        self.mempool.append(tx)
        self.persist_mempool_tx(tx)
        return tx

    def verify_transaction(self, tx, signature_hex, pubkey_hex):
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(pubkey_hex), curve=SECP256k1)
            # remove txid and signature fields before verifying content
            tx_copy = dict(tx)
            tx_copy['txid'] = tx_copy.get('txid')  # included in signed msg in our gen
            msg = json.dumps({k: tx_copy[k] for k in sorted(tx_copy) if k != 'signature'}, sort_keys=True).encode()
            sig = bytes.fromhex(signature_hex)
            return vk.verify(sig, msg)
        except Exception as e:
            return False

    def proof_of_work(self, block: Block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        target = '0' * self.difficulty
        while not computed_hash.startswith(target):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def mine_block(self, miner_address="miner1"):
        if not self.mempool:
            return None
        # reward tx (signed by network)
        reward = self._create_raw_tx("network", miner_address, 10)
        # include copy of mempool + reward
        txs = self.mempool.copy()
        txs.append(reward)
        new_block = Block(len(self.chain), txs, self.chain[-1].hash)
        start = current_time()
        new_block.hash = self.proof_of_work(new_block)
        mining_time = current_time() - start

        self.chain.append(new_block)
        self.persist_block(new_block)
        # remove mined txs from mempool
        txids = [tx['txid'] for tx in txs if tx.get('sender') != 'network']  # network txs not in mempool
        self.remove_mempool_txs(txids)
        self.mempool = self.db.load_mempool()  # reload to keep consistent
        # difficulty adjustment:
        self.adjust_difficulty()
        return new_block, mining_time

    def is_chain_valid(self, chain=None):
        chain = chain or self.chain
        for i in range(1, len(chain)):
            curr = chain[i]
            prev = chain[i - 1]
            if curr.previous_hash != prev.hash:
                return False
            if curr.hash != curr.compute_hash():
                return False
            if not curr.hash.startswith('0' * self.difficulty):
                return False
            # optional: verify tx signatures inside
            for tx in curr.transactions:
                if tx.get('sender') != 'network':
                    if not tx.get('pubkey') or not tx.get('signature'):
                        return False
                    if not self.verify_transaction(tx, tx['signature'], tx['pubkey']):
                        return False
        return True

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('sender') == address:
                    balance -= tx.get('amount', 0)
                if tx.get('recipient') == address:
                    balance += tx.get('amount', 0)
        # include mempool outgoing txs
        for tx in self.mempool:
            if tx.get('sender') == address:
                balance -= tx.get('amount', 0)
        return balance

    # difficulty adjustment: simple rule based on last interval avg time
    def adjust_difficulty(self):
        if len(self.chain) <= DIFFICULTY_ADJUST_INTERVAL:
            return
        last_index = len(self.chain) - 1
        interval_start = max(0, last_index - DIFFICULTY_ADJUST_INTERVAL)
        t_start = self.chain[interval_start].timestamp
        t_end = self.chain[last_index].timestamp
        avg_time = (t_end - t_start) / max(1, (last_index - interval_start))
        if avg_time < TARGET_BLOCK_TIME / 1.2:
            self.difficulty += 1
        elif avg_time > TARGET_BLOCK_TIME * 1.2 and self.difficulty > 1:
            self.difficulty -= 1
        # persist difficulty
        self.db.set_meta('difficulty', self.difficulty)

    # utility to import chain from external node (used by consensus)
    def replace_chain(self, new_chain_list):
        """new_chain_list is list of block dicts"""
        new_chain = []
        for b in new_chain_list:
            new_chain.append(Block(
                index=b['index'],
                transactions=b['transactions'],
                previous_hash=b['previous_hash'],
                timestamp=b['timestamp'],
                nonce=b['nonce'],
                merkle_root=b.get('merkle_root'),
                hash=b.get('hash')
            ))
        if self.is_chain_valid(new_chain) and len(new_chain) > len(self.chain):
            # save to db: delete blocks table then reinsert (simple approach)
            cur = self.db.conn.cursor()
            cur.execute('DELETE FROM blocks')
            self.db.conn.commit()
            self.chain = new_chain
            for block in self.chain:
                self.persist_block(block)
            return True
        return False

# convenience functions for key gen and signing (for client side usage)
def generate_keys():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk, vk

def sign_transaction_dict(tx_dict, sk: SigningKey):
    # tx_dict should be the tx fields except 'signature' already included maybe
    tx_copy = dict(tx_dict)
    # ensure deterministic ordering
    msg = json.dumps({k: tx_copy[k] for k in sorted(tx_copy) if k != 'signature'}, sort_keys=True).encode()
    sig = sk.sign(msg)
    return sig.hex()

def verifying_key_to_hex(vk: VerifyingKey):
    return vk.to_string().hex()

def signing_key_to_hex(sk: SigningKey):
    return sk.to_string().hex()
