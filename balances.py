from web3 import Web3
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

for acct in w3.eth.accounts:
    bal = w3.from_wei(w3.eth.get_balance(acct), "ether")
    print(f"{acct}  {bal} ETH")
