#!/usr/bin/env python3
from web3 import Web3

# Configuration
ganache_url = "http://127.0.0.1:8545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Set your accounts and private key (ensure these are correct for your Ganache instance)
account_1 = '0xd2Af7008B4fD3c0eC9e016c333D752f8D66548A1'
account_2 = '0xB9D1802e270c65218E532A562B4c02f3C162f072'
private_key = '0x1a1a65b10bdb5b19bf39f63088ffae786b4f1cb96e3d621e7f6a2997c3b8b64e'

def print_balances(label):
    """Print the Ether balances of account_1 and account_2 (in ether)"""
    balance1 = web3.eth.get_balance(account_1)
    balance2 = web3.eth.get_balance(account_2)
    print(f"{label} Balances:")
    print(f"  Account 1 ({account_1}): {web3.from_wei(balance1, 'ether')} ether")
    print(f"  Account 2 ({account_2}): {web3.from_wei(balance2, 'ether')} ether\n")

def main():
    # Check connection
    if not web3.is_connected():
        print("[ERROR] Cannot connect to Ganache.")
        return

    print(f"[+] Connected to Ganache (chainId={web3.eth.chain_id})\n")

    # 1. Print initial balances
    print_balances("Initial")

    # 2. Get current nonce for the sender
    nonce = web3.eth.get_transaction_count(account_1)
    print(f"Current nonce for account_1: {nonce}\n")

    # 3. Build and sign a transaction to transfer 1 ether
    tx = {
        'nonce': nonce,
        'to': account_2,
        'value': web3.to_wei(1, 'ether'),
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei'),
    }

    signed_tx = web3.eth.account.sign_transaction(tx, private_key)
    print("Sending transaction...")
    
    # 4. Send the transaction
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_hash_hex = web3.to_hex(tx_hash)
    print(f"Transaction sent. TX hash: {tx_hash_hex}\n")

    # 5. Wait for the transaction receipt (i.e. confirmation)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Transaction mined in block {receipt.blockNumber}\n")

    # 6. Print updated balances
    print_balances("Updated")

if __name__ == "__main__":
    main()
