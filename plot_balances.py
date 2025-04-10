import csv, collections, matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

LOG      = "tx_log.csv"
WALLETS  = "wallets.csv"

# ------------------------------------------------------------------
# 1.  Load initial balances for ordinary hosts
# ------------------------------------------------------------------
init_bal = {}
with open(WALLETS, newline="") as f:
    for r in csv.DictReader(f):
        if r["is_server"] == "False":
            init_bal[r["ip"]] = float(r.get("balance", 1000))

# use defaultdict so unknown keys start at 0.0
running_bal = collections.defaultdict(float, init_bal)

# will accumulate (event_id, balance) pairs per host
series = collections.defaultdict(list)
hosts  = set(init_bal)            # ordinary hosts only

# ------------------------------------------------------------------
# 2.  Walk through the transaction log
# ------------------------------------------------------------------
with open(LOG, newline="") as f:
    for row in csv.DictReader(f):
        ev   = int(row["event_id"])
        src  = row["src_ip"]
        dst  = row["dst_ip"]
        cost = float(row["total_eth"])

        # debit sender, credit receiver (receiver may be a server)
        running_bal[src] -= cost
        running_bal[dst] += cost

        # record the balance snapshot for every ordinary host
        for h in hosts:
            series[h].append((ev, running_bal[h]))

# ------------------------------------------------------------------
# 3.  Plot
# ------------------------------------------------------------------
for ip, pts in series.items():
    xs, ys = zip(*pts)
    plt.plot(xs, ys, label=ip)

plt.xlabel("event #")
plt.ylabel("balance (ETH)")
plt.legend()
plt.tight_layout()
plt.savefig("balances_vs_tasks.png")
plt.show()
