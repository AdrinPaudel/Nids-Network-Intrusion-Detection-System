#!/bin/sh
# ==============================================================================
# VM Attack Setup - Linux
# ==============================================================================
# Run this ON THE LINUX VM to check readiness for NIDS attack testing.
# Checks everything, asks before installing/changing anything.
#
# Usage:
#   chmod +x setup_vm.sh
#   sudo ./setup_vm.sh
# ==============================================================================

echo ""
echo "================================================================================"
echo "  VM Attack Setup Check - Linux"
echo "================================================================================"
echo "  Checks if your VM is ready to receive attacks."
echo "  Will NOT install or change anything without asking first."
echo "================================================================================"
echo ""

# ==================================================================
# Check root / sudo
# ==================================================================
if [ "$(id -u)" -ne 0 ]; then
    echo "  [ERROR] This script must be run as root (use sudo)"
    echo ""
    echo "  Usage:"
    echo "    sudo ./setup_vm.sh"
    echo ""
    exit 1
fi

echo "  [OK] Running as root"
echo ""

ISSUES=0

# ==================================================================
# Step 1: Check network interfaces and IPs
# ==================================================================
echo "Step 1: Checking network interfaces..."
echo ""

ip -4 addr show | while IFS= read -r line; do
    case "$line" in
        [0-9]*:*)
            iface=$(echo "$line" | awk -F': ' '{print $2}' | awk '{print $1}')
            ;;
        *inet\ *)
            ip_addr=$(echo "$line" | awk '{print $2}' | cut -d'/' -f1)
            echo "  Interface: $iface  ->  IP: $ip_addr"
            ;;
    esac
done

echo ""

# Try to identify VM IP
VM_IP=""
for iface in $(ip -o -4 addr show | awk '{print $2}' | sort -u); do
    ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
    case "$ip_addr" in
        127.*)
            ;;
        192.168.56.*|192.168.57.*|10.0.2.*|172.*)
            VM_IP="$ip_addr"
            VM_IFACE="$iface"
            ;;
        *)
            if [ -z "$VM_IP" ]; then
                VM_IP="$ip_addr"
                VM_IFACE="$iface"
            fi
            ;;
    esac
done

if [ -n "$VM_IP" ]; then
    echo "  -> Your VM IP (for attacks): $VM_IP (on $VM_IFACE)"
else
    echo "  [!] Could not auto-detect VM IP"
    echo "      Look at the interfaces above and pick the one your host can reach"
    echo ""
    echo "      If no IP on second adapter, run:"
    echo "        sudo dhclient enp0s8"
    echo "      (replace enp0s8 with your second adapter name)"
    ISSUES=$((ISSUES + 1))
fi
echo ""

# ==================================================================
# Step 2: Check SSH Server
# ==================================================================
echo "Step 2: Checking SSH Server (needed for Brute Force attack)..."
echo ""

SSH_INSTALLED=false
SSH_RUNNING=false

# Check if installed
if dpkg -l openssh-server 2>/dev/null | grep -q "^ii"; then
    SSH_INSTALLED=true
    echo "  [OK] openssh-server is installed"
elif rpm -q openssh-server >/dev/null 2>&1; then
    SSH_INSTALLED=true
    echo "  [OK] openssh-server is installed"
elif command -v sshd > /dev/null 2>&1; then
    SSH_INSTALLED=true
    echo "  [OK] sshd binary found"
fi

# Check if running
if [ "$SSH_INSTALLED" = true ]; then
    if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
        SSH_RUNNING=true
        echo "  [OK] SSH service is running"
    else
        echo "  [!] SSH is installed but NOT running"
        echo ""
        printf "  Do you want to start SSH? [y/n]: "
        read -r answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null
            systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null
            if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
                SSH_RUNNING=true
                echo "  [OK] SSH started"
            else
                echo "  [!] Failed to start SSH"
            fi
        else
            echo "  [SKIP] SSH not started"
            echo "  To start it manually:"
            echo "    sudo systemctl start ssh"
        fi
    fi
else
    echo "  [!] openssh-server is NOT installed"
    echo "      This is needed for the Brute Force attack."
    echo ""
    printf "  Do you want to install openssh-server? [y/n]: "
    read -r answer
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        echo "  Installing..."
        if command -v apt-get > /dev/null 2>&1; then
            apt-get update -qq
            apt-get install -y -qq openssh-server
        elif command -v dnf > /dev/null 2>&1; then
            dnf install -y openssh-server
        elif command -v yum > /dev/null 2>&1; then
            yum install -y openssh-server
        elif command -v pacman > /dev/null 2>&1; then
            pacman -S --noconfirm openssh
        else
            echo "  [!] Unknown package manager — install manually"
        fi

        # Check if it worked
        if command -v sshd > /dev/null 2>&1; then
            SSH_INSTALLED=true
            echo "  [OK] Installed"
            printf "  Start SSH now? [y/n]: "
            read -r answer2
            if [ "$answer2" = "y" ] || [ "$answer2" = "Y" ]; then
                systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null
                systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null
                SSH_RUNNING=true
                echo "  [OK] SSH started"
            fi
        else
            echo "  [!] Installation failed"
        fi
    else
        echo "  [SKIP] Not installing SSH"
        echo "  To install manually:"
        echo "    sudo apt install openssh-server"
        echo "    sudo systemctl start ssh"
        ISSUES=$((ISSUES + 1))
    fi
fi
echo ""

# ==================================================================
# Step 3: Check net-tools
# ==================================================================
echo "Step 3: Checking network tools..."
echo ""

if command -v ifconfig > /dev/null 2>&1; then
    echo "  [OK] net-tools installed"
else
    echo "  [!] net-tools not installed (optional — for ifconfig)"
    echo "      To install: sudo apt install net-tools"
fi
echo ""

# ==================================================================
# Step 4: Check libpcap
# ==================================================================
echo "Step 4: Checking libpcap (needed by NIDS for packet capture)..."
echo ""

LIBPCAP_FOUND=false
if ldconfig -p 2>/dev/null | grep -q libpcap; then
    LIBPCAP_FOUND=true
elif [ -f /usr/lib/x86_64-linux-gnu/libpcap.so ] || \
     [ -f /usr/lib/x86_64-linux-gnu/libpcap.so.1 ] || \
     [ -f /usr/lib/libpcap.so ] || \
     [ -f /usr/lib/libpcap.so.1 ]; then
    LIBPCAP_FOUND=true
fi

if [ "$LIBPCAP_FOUND" = true ]; then
    echo "  [OK] libpcap found"
else
    echo "  [!] libpcap NOT found — NIDS packet capture won't work"
    echo "      To install: sudo apt install libpcap-dev"
    ISSUES=$((ISSUES + 1))
fi
echo ""

# ==================================================================
# Step 5: Check NIDS project
# ==================================================================
echo "Step 5: Checking NIDS project..."
echo ""

NIDS_DIR=""
if [ -d "$HOME/Nids" ]; then
    NIDS_DIR="$HOME/Nids"
elif [ -d "$HOME/nids" ]; then
    NIDS_DIR="$HOME/nids"
elif [ -d "$HOME/NIDS" ]; then
    NIDS_DIR="$HOME/NIDS"
fi

if [ -n "$NIDS_DIR" ]; then
    echo "  [OK] NIDS project found at: $NIDS_DIR"

    if [ -d "$NIDS_DIR/venv" ]; then
        echo "  [OK] Virtual environment exists"
    else
        echo "  [!] No venv — run setup/setup.sh in the NIDS project first"
        ISSUES=$((ISSUES + 1))
    fi

    if [ -f "$NIDS_DIR/trained_model/random_forest_model.joblib" ]; then
        echo "  [OK] Default model (5-class: Benign, Botnet, Brute Force, DDoS, DoS)"
    else
        echo "  [!] No default model found in trained_model/"
        ISSUES=$((ISSUES + 1))
    fi

    if [ -f "$NIDS_DIR/trained_model_all/random_forest_model.joblib" ]; then
        echo "  [OK] All model (6-class: + Infilteration)"
    else
        echo "  [-] No 6-class model (optional — only needed for infiltration detection)"
    fi
else
    echo "  [!] NIDS project not found in home directory"
    echo "      Make sure you git cloned it and ran setup/setup.sh"
    ISSUES=$((ISSUES + 1))
fi
echo ""

# ==================================================================
# Step 6: Check packet capture permissions
# ==================================================================
echo "Step 6: Checking packet capture permissions..."
echo ""

if [ -n "$NIDS_DIR" ] && [ -d "$NIDS_DIR/venv" ]; then
    PYTHON_PATH=$(readlink -f "$NIDS_DIR/venv/bin/python3" 2>/dev/null || readlink -f "$NIDS_DIR/venv/bin/python" 2>/dev/null)

    if [ -n "$PYTHON_PATH" ] && [ -f "$PYTHON_PATH" ]; then
        # Check if cap_net_raw is already set
        CAPS=$(getcap "$PYTHON_PATH" 2>/dev/null || echo "")
        if echo "$CAPS" | grep -q "cap_net_raw"; then
            echo "  [OK] cap_net_raw already set on: $PYTHON_PATH"
            echo "  (You can run classification.py without sudo)"
        else
            echo "  [!] cap_net_raw NOT set on: $PYTHON_PATH"
            echo "      Without this, you must use sudo to run NIDS."
            echo ""
            printf "  Grant packet capture permission? [y/n]: "
            read -r answer
            if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
                setcap cap_net_raw,cap_net_admin=eip "$PYTHON_PATH" 2>/dev/null
                if getcap "$PYTHON_PATH" 2>/dev/null | grep -q "cap_net_raw"; then
                    echo "  [OK] Granted cap_net_raw"
                    echo "  (You can now run classification.py without sudo)"
                else
                    echo "  [!] Failed — use sudo to run NIDS instead"
                fi
            else
                echo "  [SKIP] Not granting permissions"
                echo "  To do it manually:"
                echo "    sudo setcap cap_net_raw,cap_net_admin=eip $PYTHON_PATH"
                echo "  Or just use sudo:"
                echo "    sudo ./venv/bin/python classification.py"
            fi
        fi
    else
        echo "  [!] Could not find venv python binary"
        echo "      Use sudo to run: sudo ./venv/bin/python classification.py"
    fi
else
    echo "  [SKIP] No NIDS venv found"
    echo "  Use sudo to run: sudo ./venv/bin/python classification.py"
fi
echo ""

# ==================================================================
# Summary
# ==================================================================
echo "================================================================================"
if [ "$ISSUES" -eq 0 ]; then
    echo "  ALL CHECKS PASSED — VM is ready for attacks!"
else
    echo "  CHECKS DONE — $ISSUES issue(s) found (see above)"
fi
echo "================================================================================"
echo ""

if [ -n "$VM_IP" ]; then
    echo "  Your VM IP: $VM_IP"
else
    echo "  Your VM IP: run 'ip addr show' to find it"
fi

echo ""
echo "  To start NIDS:"

if [ -n "$NIDS_DIR" ]; then
    echo "    cd $NIDS_DIR"
else
    echo "    cd ~/Nids"
fi

echo "    source venv/bin/activate"
echo "    sudo ./venv/bin/python classification.py --duration 600"
echo ""
echo "  Then from your attacker machine:"
if [ -n "$VM_IP" ]; then
    echo "    python run_all_attacks.py $VM_IP"
else
    echo "    python run_all_attacks.py <VM_IP>"
fi
echo ""
echo "================================================================================"
echo ""
