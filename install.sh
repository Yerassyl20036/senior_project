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

# ------------------------------------------------------------------------------
# 7) Mininet-WiFi
# ------------------------------------------------------------------------------
echo ""
echo "===== STEP 6: Mininet-WiFi ====="

# Instead of cloning into $HOME/mininet-wifi, clone locally in the current project dir.
# We'll store the current script directory in a variable:
# SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"   # e.g. /home/user/Desktop/sdnblockhain

# MWIFI_DIR="${SCRIPT_DIR}/mininet-wifi"       # the local path for mininet-wifi

# if [ -d "$MWIFI_DIR" ]; then
#   echo "Mininet-WiFi directory already exists at: $MWIFI_DIR"
#   echo "Skipping clone."
# else
#   echo "Cloning Mininet-WiFi repo into $MWIFI_DIR ..."
#   git clone https://github.com/intrig-unicamp/mininet-wifi.git "$MWIFI_DIR"
#   if [ $? -ne 0 ]; then
#     echo "[ERROR] Cloning Mininet-WiFi repo failed."
#     exit 1
#   fi
# fi

# cd "$MWIFI_DIR" || exit
# echo "Installing Mininet-WiFi with 'sudo util/install.sh -Wlnfv'..."
# sudo util/install.sh -Wlnfv
# if [ $? -ne 0 ]; then
#   echo "[ERROR] Mininet-WiFi installation failed."
#   exit 1
# fi

# # Step back to the project directory
# cd "$SCRIPT_DIR" || exit
# echo "Done installing Mininet-WiFi locally at $MWIFI_DIR"

# DO A MANUAL INSTALLATION OF MININET-WIFI WITH CONTAINERNET

# ------------------------------------------------------------------------------
# 8) Ganache (via NPM)
# ------------------------------------------------------------------------------
echo ""
echo "===== STEP 7: Ganache (via NPM) ====="
echo "Installing Ganache globally with npm..."
sudo npm install --global ganache
sudo npm install --global truffle
pip install web3
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
