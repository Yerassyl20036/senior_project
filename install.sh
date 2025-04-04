# Combined installation script for:
#   1) Mininet
#   2) Docker
#   3) Floodlight (via Docker)
#   4) NPM + Ganache
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# Check install.log after completion to see any errors or warnings.

# ------------------------------------------------------------------------------
# 1) Send all output (stdout and stderr) to a single log file
# ------------------------------------------------------------------------------
LOGFILE="install.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "===== Starting installation at $(date) ====="

# ------------------------------------------------------------------------------
# 2) System prep: Update packages and install base dependencies
# ------------------------------------------------------------------------------
echo ""
echo "===== STEP 1: System Update and Dependencies ====="
sudo apt-get update && sudo apt-get upgrade -y
if [ $? -ne 0 ]; then
  echo "[ERROR] System update/upgrade failed."
fi

# Attempt installing required packages
sudo apt-get install -y git curl ansible nodejs npm
if [ $? -ne 0 ]; then
  echo "[ERROR] Installing base packages (git, curl, ansible, nodejs, npm) failed."
fi

# ------------------------------------------------------------------------------
# 3) Mininet
# ------------------------------------------------------------------------------
echo ""
echo "===== STEP 2: Mininet Installation ====="

if [ -d "$HOME/mininet" ]; then
  echo "Mininet directory already exists. Skipping clone."
else
  echo "Cloning Mininet repo..."
  git clone https://github.com/mininet/mininet.git "$HOME/mininet"
  if [ $? -ne 0 ]; then
    echo "[ERROR] Cloning mininet repo failed."
  fi
fi

echo "Installing Mininet (full install) with '-q'..."
cd "$HOME/mininet" || true
sudo ./util/install.sh -a
if [ $? -ne 0 ]; then
  echo "[ERROR] Mininet installation failed."
fi
cd ~

# ------------------------------------------------------------------------------
# 4) Docker
# ------------------------------------------------------------------------------
echo ""
echo "===== STEP 3: Docker Installation ====="

# Remove old docker packages if they exist (won't stop script on error)
sudo apt-get remove -y docker docker-engine docker.io containerd runc || true

# Install Docker as indicated
sudo apt-get install -y ca-certificates
sudo mkdir -p /etc/apt/keyrings

curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo tee /etc/apt/keyrings/docker.asc > /dev/null
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
if [ $? -ne 0 ]; then
  echo "[ERROR] Docker installation failed."
fi

# Test Docker
echo "Testing Docker with 'hello-world' container..."
sudo docker run hello-world
if [ $? -ne 0 ]; then
  echo "[ERROR] Docker 'hello-world' test failed."
fi

# ------------------------------------------------------------------------------
# 5) Floodlight Controller (via Docker)
# ------------------------------------------------------------------------------
echo ""
echo "===== STEP 4: Floodlight (Docker) ====="
echo "Pulling Floodlight Docker image 'piyushk2001/floodlight-controller'..."
sudo docker pull piyushk2001/floodlight-controller
if [ $? -ne 0 ]; then
  echo "[ERROR] Pulling Floodlight Docker image failed."
fi


# 1) Figure out directory of this script
# This ensures we always work relative to *this* file’s location
# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# # 2) Define where to clone
# MWIFI_DIR="$SCRIPT_DIR/mininet-wifi"
# CONTAINERNET_DIR="$SCRIPT_DIR/containernet"

# # ------------------------------------------------------------------------------
# # 6) Mininet-WiFi
# # ------------------------------------------------------------------------------
# echo ""
# echo "===== STEP 5: Mininet-WiFi ====="

# echo "Cloning Mininet-WiFi repo into $MWIFI_DIR ..."
# git clone https://github.com/intrig-unicamp/mininet-wifi.git "$MWIFI_DIR"

# echo "Installing Mininet-WiFi (sudo util/install.sh -Wlnfv) ..."
# cd "$MWIFI_DIR"
# sudo ./util/install.sh -Wlnfv
# cd "$SCRIPT_DIR"

# echo "Done installing Mininet-WiFi locally at $MWIFI_DIR"

# # ------------------------------------------------------------------------------
# # 7) Containernet
# # ------------------------------------------------------------------------------
# echo ""
# echo "===== STEP 6: Containernet ====="

# echo "Cloning Containernet repo into $CONTAINERNET_DIR ..."
# git clone https://github.com/containernet/containernet.git "$CONTAINERNET_DIR"

# echo "Installing Containernet (sudo ansible-playbook -i 'localhost,' -c local install.yml) ..."
# cd "$CONTAINERNET_DIR"
# sudo ansible-playbook -i "localhost," -c local ansible/install.yml
# cd "$SCRIPT_DIR"

# echo "Done installing Containernet locally at $CONTAINERNET_DIR"


# ------------------------------------------------------------------------------
# 7) Ganache (via NPM)
# ------------------------------------------------------------------------------
echo ""
echo "===== STEP 7: Ganache (via NPM) ====="
echo "Installing Ganache globally with npm..."
sudo npm install --global ganache
sudo npm install --global truffle
sudo pip install web3
pip install web3
sudo pip install networkx
pip install networkx
if [ $? -ne 0 ]; then
  echo "[ERROR] Ganache installation failed."
fi

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------
echo ""
echo "===== Installation Completed at $(date) ====="
echo "All console output has been logged to $LOGFILE."
echo "Check for any [ERROR] lines in that file if something didn't succeed."
