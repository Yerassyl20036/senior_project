import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('TkAgg')

# Read CSV. Assuming first row is header.
df = pd.read_csv("req_stats.csv", delimiter=",", names=["elapsed_sec", "total_requests", "successful_transfers"], skiprows=1)

# Convert the elapsed_sec column to a timedelta.
df["time"] = pd.to_timedelta(df["elapsed_sec"], unit="s")

# Set this new time column as the index.
df.set_index("time", inplace=True)

# Resample in 1s bins. Use '1s' instead of '1S' to avoid FutureWarning.
df_resampled = df.resample("1s").max().fillna(method="ffill").reset_index()

# Convert the 'time' column back to seconds for plotting if desired.
df_resampled["elapsed_sec"] = df_resampled["time"].dt.total_seconds()

# Plot the curves
plt.figure(figsize=(8,6))
plt.plot(df_resampled["elapsed_sec"], df_resampled["total_requests"], '-ks', label="(Ab)normal Requests")
plt.plot(df_resampled["elapsed_sec"], df_resampled["successful_transfers"], '-or', label="Normal Requests (SDBlockEdge)")
plt.xlabel("Time (Sec.)")
plt.ylabel("Number of Requests")
plt.title("Request Counters vs. Time")
plt.legend()
plt.grid(True)

# Save the plot to a PNG file.
plt.savefig("request_counters.png", dpi=300)
plt.show()
