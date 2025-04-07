#!/usr/bin/env python3
import csv
import sys
from pathlib import Path

import requests
from eth_account import Account

# ---------- CONFIG -------------------------------------------------
FLOODLIGHT_URL = "http://127.0.0.1:8080/wm/device/"
MNEMONIC = (
    "spend able critic rebuild flight mail trim brush vault "
    "solution juice jeans"
).strip()
HD_PATH = "m/44'/60'/0'/0/{}"
OUT_CSV = Path("wallets.csv")
# -------------------------------------------------------------------

Account.enable_unaudited_hdwallet_features()


def fetch_devices():
    try:
        r = requests.get(FLOODLIGHT_URL, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[ERROR] cannot fetch devices: {e}")
        return []


def collect_hosts():
    """Return list of dicts: mac, ip, is_server (only hosts with IPv4)."""
    data     = fetch_devices()
    devices  = data.get("devices", data) if isinstance(data, dict) else data
    hosts    = []

    for dev in devices:
        if not isinstance(dev, dict):
            continue

        aps = dev.get("attachmentPoint", [])
        if not aps:
            continue                                  # skip phantom rows

        ap0   = aps[0]
        port  = ap0.get("port")
        is_server = (port != 1)
        if ap0.get("switch") is None and ap0.get("switchDPID") is None:
            continue                                  # no switch info

        ipv4  = dev.get("ipv4", [])
        if not ipv4:
            continue                                  # skip hosts w/o IPv4

        ip    = ipv4[0]

        mac   = dev.get("mac", [])
        if isinstance(mac, list):
            mac = mac[0] if mac else ""
        mac = str(mac)

        print(f"[INFO] {mac} {ip} port={port} switch={ap0.get('switch')}")
        hosts.append(dict(mac=mac, ip=ip, is_server=is_server))

    # # guarantee at least one server
    # if hosts and not any(h["is_server"] for h in hosts):
    #     hosts[-1]["is_server"] = True

    hosts.sort(key=lambda h: (h["ip"]))
    return hosts

def derive_wallet(idx):
    acct = Account.from_mnemonic(MNEMONIC, account_path=HD_PATH.format(idx))
    return acct.address, acct.key.hex()


def main():
    hosts = collect_hosts()
    if not hosts:
        print("[ERROR] No valid hosts after filtering")
        sys.exit(1)

    rows = []
    for idx, h in enumerate(hosts):
        addr, pk = derive_wallet(idx)
        rows.append(
            dict(mac=h["mac"],
                 ip=h["ip"],
                 is_server=h["is_server"],
                 idx=idx,
                 address=addr,
                 privkey=pk)
        )

    with OUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["mac", "ip", "is_server", "idx", "address", "privkey"]
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] wrote {OUT_CSV} ({len(rows)} rows)")
    for r in rows:
        print(f"{r['mac']}  {r['ip']}  server={r['is_server']}  idx={r['idx']}")

if __name__ == "__main__":
    main()
