# 1) Figure out directory of this script
# This ensures we always work relative to *this* file’s location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2) Define where to clone
MWIFI_DIR="$SCRIPT_DIR/mininet-wifi"
CONTAINERNET_DIR="$SCRIPT_DIR/containernet"

# ------------------------------------------------------------------------------
# 6) Mininet-WiFi
# ------------------------------------------------------------------------------
echo ""
echo "===== STEP 5: Mininet-WiFi ====="

echo "Cloning Mininet-WiFi repo into $MWIFI_DIR ..."
git clone https://github.com/intrig-unicamp/mininet-wifi.git "$MWIFI_DIR"

echo "Installing Mininet-WiFi (sudo util/install.sh -Wlnfv) ..."
cd "$MWIFI_DIR"
sudo ./util/install.sh -Wlnfv
cd "$SCRIPT_DIR"

echo "Done installing Mininet-WiFi locally at $MWIFI_DIR"

# ------------------------------------------------------------------------------
# 7) Containernet
# ------------------------------------------------------------------------------
echo ""
echo "===== STEP 6: Containernet ====="

echo "Cloning Containernet repo into $CONTAINERNET_DIR ..."
git clone https://github.com/containernet/containernet.git "$CONTAINERNET_DIR"

echo "Installing Containernet (sudo ansible-playbook -i 'localhost,' -c local install.yml) ..."
cd "$CONTAINERNET_DIR"
sudo ansible-playbook -i "localhost," -c local ansible/install.yml
cd "$SCRIPT_DIR"

echo "Done installing Containernet locally at $CONTAINERNET_DIR"