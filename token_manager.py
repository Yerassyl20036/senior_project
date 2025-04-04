#!/usr/bin/env python3

import json
from web3 import Web3, HTTPProvider
from visualize import FloodlightVisualizer

def main():
    # 1) Build the network topology from Floodlight
    fv = FloodlightVisualizer()
    fv.build_topology()

    # 2) Collect the host labels
    host_labels = [
        node for node,data in fv.topology.nodes(data=True)
        if data.get("type") == "host"
    ]
    print("Discovered host labels:", host_labels)

    # 3) Connect to Ganache
    w3 = Web3(HTTPProvider("http://127.0.0.1:8545"))
    if not w3.is_connected():
        print("[Error] Could not connect to Ganache at 127.0.0.1:8545. Is it running?")
        return

    # Let's see the chain ID Ganache is actually using
    chain_id = w3.eth.chain_id
    print("Ganache chain_id is:", chain_id)

    # 4) Load MyToken contract info (ABI + address)
    try:
        with open("sdn-blockchain/build/contracts/MyToken.json", "r") as f:
            contract_json = json.load(f)
    except FileNotFoundError:
        print("[Error] Could not find build/contracts/MyToken.json. Did you run `truffle migrate`?")
        return

    abi = contract_json["abi"]
    networks_info = contract_json.get("networks", {})

    # 5) Dynamically pick the correct contract address
    chain_id_str = str(chain_id)
    if chain_id_str in networks_info:
        # Great, the chain ID in Ganache matches an entry in MyToken.json
        contract_address = networks_info[chain_id_str]["address"]
        print(f"Found matching network ID {chain_id_str} in MyToken.json")
    else:
        print(f"[Warning] No entry for chain ID {chain_id_str} in MyToken.json.")
        print("Falling back to the last network entry found.")
        # If there's at least one network entry, pick the last one
        if networks_info:
            # Sort keys or just pick the last. We'll pick last:
            last_net_id = list(networks_info.keys())[-1]
            contract_address = networks_info[last_net_id]["address"]
            print(f"Using network {last_net_id} => address {contract_address}")
        else:
            # No network info at all
            print("[Warning] `networks` is empty—no known contract address!")
            contract_address = "0x0000000000000000000000000000000000000000"

    print("Using contract address:", contract_address)
    contract = w3.eth.contract(address=contract_address, abi=abi)

    # 6) Use one of Ganache’s default accounts to pay for gas
    #    Replace with your actual private key
    ganache_private_key = "0xa52f97a5edd5fb284bb61f789b36a5e74fbaf0a0d229e6836f3df9d19ee17310"  # e.g. from Ganache output
    acct = w3.eth.account.from_key(ganache_private_key)
    w3.eth.default_account = acct.address

    # 7) For each host, create ephemeral addresses => mint tokens
    host_addresses = {}
    for label in host_labels:
        new_acct = w3.eth.account.create(label)  # seeded for reproducibility
        host_addresses[label] = new_acct.address

    for label, host_addr in host_addresses.items():
        # Build the mint transaction
        tx = contract.functions.mint(host_addr, 1000).build_transaction({
            'from': acct.address,
            'nonce': w3.eth.get_transaction_count(acct.address),
            'gas': 300000,
            'gasPrice': w3.to_wei('1', 'gwei'),
        })
        # Sign & send
        signed_tx = acct.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"[Minted] 1000 tokens for {label} => {host_addr}, block {receipt.blockNumber}")

    # 8) Query final balances
    for label, host_addr in host_addresses.items():
        try:
            bal = contract.functions.balanceOf(host_addr).call()
            print(f"{label} => {host_addr} has {bal} tokens")
        except:
            print(f"[Error] Could not read balanceOf({host_addr}). "
                  "Is the contract address correct or function absent?")

if __name__ == "__main__":
    main()
