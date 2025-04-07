#!/usr/bin/env python3
import sys
from pathlib import Path

from eth_account import Account
from web3 import Web3

# ---------- configurable ----------
GANACHE_RPC  = "http://127.0.0.1:8545"
NUM_ACCOUNTS = 10                     # how many to export
OUTPUT_FILE  = Path("wallets.txt")

# Hard‑coded 12‑word mnemonic (Ganache default example)
HARDCODED_MNEMONIC = (
    "spend able critic rebuild flight mail trim brush vault solution juice jeans"
)
ASK_FOR_MNEMONIC   = False            # do NOT prompt
# ----------------------------------

HD_PATH_TEMPLATE = "m/44'/60'/0'/0/{}"    # Ganache’s derivation path

Account.enable_unaudited_hdwallet_features()   #  <<–– add this line

def get_mnemonic() -> str:
    """Return either the hard‑coded or prompted mnemonic."""
    if not ASK_FOR_MNEMONIC and HARDCODED_MNEMONIC:
        return HARDCODED_MNEMONIC.strip()
    # (Won’t reach here when ASK_FOR_MNEMONIC = False)
    from getpass import getpass
    print("Enter the 12‑word Ganache mnemonic:")
    return getpass("mnemonic> ").strip()

def derive_accounts(mnemonic: str, n: int):
    """Yield (index, address, privkey_hex) for first n accounts."""
    for idx in range(n):
        acct = Account.from_mnemonic(
            mnemonic, account_path=HD_PATH_TEMPLATE.format(idx)
        )
        yield idx, acct.address, acct.key.hex()

def main():
    # 1) Check Ganache is up
    w3 = Web3(Web3.HTTPProvider(GANACHE_RPC))
    if not w3.is_connected():
        print(f"[ERROR] Cannot connect to Ganache at {GANACHE_RPC}")
        sys.exit(1)
    print(f"[+] Connected to Ganache  chainId={w3.eth.chain_id}")

    # 2) Get mnemonic (hard‑coded here)
    mnemonic = get_mnemonic()
    if len(mnemonic.split()) < 12:
        print("[ERROR] mnemonic seems too short.")
        sys.exit(1)

    # 3) Derive accounts
    rows = list(derive_accounts(mnemonic, NUM_ACCOUNTS))

    # 4) Write to file
    with OUTPUT_FILE.open("w") as f:
        f.write("# idx  address                                   private_key\n")
        for idx, addr, pk in rows:
            f.write(f"{idx:>2}  {addr}  {pk}\n")

    print(f"[+] Wrote {len(rows)} wallets to {OUTPUT_FILE.resolve()}")

    # 5) Show first few
    for idx, addr, pk in rows[:3]:
        print(f"  idx={idx}  {addr}  {pk[:12]}…")

if __name__ == "__main__":
    main()
