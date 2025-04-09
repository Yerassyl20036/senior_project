# Token Based Approach for Resource Management in IoT Edge Networks

## Project Description
This project implements a token-based resource management system for IoT Edge Networks using SDN (Software-Defined Networking) and blockchain technologies. It combines Mininet-WiFi for network emulation, Floodlight as the SDN controller, and a private blockchain using Ganache for token management.

## System Requirements
- Ubuntu 22.04 LTS
- Git
- Python 3.x

## Installation

### Step 1: Prepare Installation Scripts
```bash
sudo chmod +x install.sh install2.sh
```
### Run First Installation Script
```bash
./install.sh
 ```
This script installs:
- Basic system dependencies
- Mininet
- Docker
- Floodlight Controller (Docker image)
- Ganache and Truffle (Blockchain tools)

###  Run Second Installation Script
```bash
./install2.sh
 ```
Note: During installation, you may be prompted about previous patches. Answer 'y' to all three questions if prompted.
After successful installation, the following directories should be created:
- containernet/
- mac80211_hwsim_mgmt/
- mininet-wifi/
- openflow/
- wmediumd/
- sdn-blockchain/ (for Ganache private blockchain)

## Project Structure After Installation
```plaintext
senior_project/
├── containernet/
├── mac80211_hwsim_mgmt/
├── mininet-wifi/
├── openflow/
├── wmediumd/
├── sdn-blockchain/
│   ├── build/
│   ├── contracts/
│   ├── migrations/
│   ├── test/
│   └── truffle-config.js
├── custom_topo.py
├── main.py
├── balances.py
├── install.sh
├── install2.sh
└── docker-compose.yml
 ```

## Running the Project
### 1. Start the Floodlight Controller
```bash
sudo docker compose up
 ```

### 2. Run Custom Network Topology
```bash
sudo python custom_topo.py
 ```

### 3. Run Local Blockchain
```bash
cd sdn-blockchain
ganache
 ```

### 4. Visualize the Network Topology and simulate token transfer
```bash
python main.py
 ```

### 5. Check the tokens on each balance on ganache local blockchain
```bash
python balances.py
 ```