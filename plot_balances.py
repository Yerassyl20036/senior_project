import csv
import collections
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from pathlib import Path

LOG = Path("tx_log.csv")
WALLETS = Path("wallets.csv")

DOCKER_HOSTS = {"10.0.0.7", "10.0.0.8"}

def plot_host_balance():
    init_bal = {}
    if WALLETS.exists():
        with WALLETS.open(newline="") as f:
            for r in csv.DictReader(f):
                if r["is_server"] == "False":
                    init_bal[r["ip"]] = float(r.get("balance", 1000))

    running_bal = collections.defaultdict(float, init_bal)
    series = collections.defaultdict(list)
    hosts = set(init_bal)

    if LOG.exists():
        with LOG.open(newline="") as f:
            for row in csv.DictReader(f):
                ev = int(row["event_id"])
                src = row["src_ip"]
                dst = row["dst_ip"]
                cost = float(row["total_eth"])

                running_bal[src] -= cost
                if dst in hosts:
                    running_bal[dst] += cost

                for h in hosts:
                    series[h].append((ev, running_bal[h]))

    for ip, pts in series.items():
        xs, ys = zip(*pts)
        plt.plot(xs, ys, label=ip)

    plt.title("IoT devices ganache balance vs. task events")
    plt.xlabel("event #")
    plt.ylabel("balance (ETH)")
    plt.grid(True, linestyle="--", alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig("balances_vs_tasks.png")
    plt.show()

def plot_docker_balances():
    docker_bal = {ip: 0.0 for ip in DOCKER_HOSTS}
    if WALLETS.exists():
        with WALLETS.open(newline="") as f:
            for row in csv.DictReader(f):
                ip = row["ip"]
                if ip in DOCKER_HOSTS:
                    docker_bal[ip] = float(row.get("balance", 0.0))

    series = {ip: [] for ip in DOCKER_HOSTS}
    if LOG.exists():
        with LOG.open(newline="") as f:
            for row in csv.DictReader(f):
                ev = int(row["event_id"])
                src = row["src_ip"]
                dst = row["dst_ip"]
                cost = float(row["total_eth"])

                if dst in DOCKER_HOSTS:
                    docker_bal[dst] += cost

                for ip in DOCKER_HOSTS:
                    series[ip].append((ev, docker_bal[ip]))

    plt.figure(figsize=(8,4))
    for ip, pts in series.items():
        xs, ys = zip(*pts)
        plt.plot(xs, ys, label=ip)

    plt.title("Docker‑host token balance vs. task events")
    plt.xlabel("event #")
    plt.ylabel("balance (ETH)")
    plt.grid(True, linestyle="--", alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig("docker_balances_vs_tasks.png")
    plt.show()

if __name__ == "__main__":
    plot_host_balance()
    plot_docker_balances()
