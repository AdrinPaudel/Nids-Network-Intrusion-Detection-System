#!/bin/sh
# ==============================================================================
# Device Attack Setup - Linux
# ==============================================================================
# Run this ON THE TARGET DEVICE (VM or server) to check readiness for NIDS
# attack testing. Works on both virtual machines and physical servers.
# Checks everything, asks before installing/changing anything.
#
# Usage:
#   chmod +x setup_device.sh
#   sudo sh ./setup_device.sh
# ==============================================================================

echo ""
echo "================================================================================"
echo "  Device Attack Setup Check - Linux"
echo "================================================================================"
echo "  Checks if your device (VM or server) is ready to receive attacks."
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
    echo "    sudo sh ./setup_device.sh"
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

echo "  [INFO] Recommended network interface setup:"
echo "    For VMs:     At least 1 Host-Only adapter (attacker-to-target communication)"
echo "                 + 1 Bridged or NAT adapter (internet access)"
echo "    For servers: At least 1 NIC with a reachable IP from your attacker machine"
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

# Try to identify device IP
DEVICE_IP=""
for iface in $(ip -o -4 addr show | awk '{print $2}' | sort -u); do
    ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
    case "$ip_addr" in
        127.*)
            ;;
        192.168.56.*|192.168.57.*|10.0.2.*|172.*)
            DEVICE_IP="$ip_addr"
            DEVICE_IFACE="$iface"
            ;;
        *)
            if [ -z "$DEVICE_IP" ]; then
                DEVICE_IP="$ip_addr"
                DEVICE_IFACE="$iface"
            fi
            ;;
    esac
done

if [ -n "$DEVICE_IP" ]; then
    echo "  -> Your device IP (for attacks): $DEVICE_IP (on $DEVICE_IFACE)"
else
    echo "  [!] Could not auto-detect device IP"
    echo "      Look at the interfaces above and pick the one your attacker can reach"
    echo ""
    echo "      For VMs — if no IP on second adapter, run:"
    echo "        sudo dhclient enp0s8"
    echo "      (replace enp0s8 with your second adapter name)"
    echo ""
    echo "      For servers — make sure at least one NIC has an IP reachable from attacker"
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
# Step 3: Check Web Server (needed for DoS/DDoS HTTP attacks)
# ==================================================================
echo "Step 3: Checking Web Server (needed for DoS and DDoS attacks)..."
echo ""

WEB_INSTALLED=false
WEB_RUNNING=false

# Check Apache
if dpkg -l apache2 2>/dev/null | grep -q "^ii"; then
    WEB_INSTALLED=true
    WEB_NAME="apache2"
    echo "  [OK] Apache2 is installed"
elif rpm -q httpd >/dev/null 2>&1; then
    WEB_INSTALLED=true
    WEB_NAME="httpd"
    echo "  [OK] Apache (httpd) is installed"
fi

# Check Nginx if no Apache
if [ "$WEB_INSTALLED" = false ]; then
    if dpkg -l nginx 2>/dev/null | grep -q "^ii"; then
        WEB_INSTALLED=true
        WEB_NAME="nginx"
        echo "  [OK] Nginx is installed"
    elif rpm -q nginx >/dev/null 2>&1; then
        WEB_INSTALLED=true
        WEB_NAME="nginx"
        echo "  [OK] Nginx is installed"
    fi
fi

if [ "$WEB_INSTALLED" = true ]; then
    if systemctl is-active --quiet "$WEB_NAME" 2>/dev/null; then
        WEB_RUNNING=true
        echo "  [OK] $WEB_NAME service is running"
    else
        echo "  [!] $WEB_NAME is installed but NOT running"
        echo ""
        printf "  Do you want to start $WEB_NAME? [y/n]: "
        read -r answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            systemctl enable "$WEB_NAME" 2>/dev/null
            systemctl start "$WEB_NAME" 2>/dev/null
            if systemctl is-active --quiet "$WEB_NAME" 2>/dev/null; then
                WEB_RUNNING=true
                echo "  [OK] $WEB_NAME started"
            else
                echo "  [!] Failed to start $WEB_NAME"
            fi
        else
            echo "  [SKIP] $WEB_NAME not started"
            echo "  To start it manually:"
            echo "    sudo systemctl start $WEB_NAME"
        fi
    fi
else
    echo "  [!] No web server installed"
    echo "      A web server is REQUIRED for DoS and DDoS attacks."
    echo "      (DoS uses HTTP Hulk/Slowloris/GoldenEye, DDoS uses LOIC/HOIC HTTP floods)"
    echo ""
    printf "  Do you want to install Apache2? [y/n]: "
    read -r answer
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        echo "  Installing apache2..."
        if command -v apt-get > /dev/null 2>&1; then
            apt-get update -qq
            apt-get install -y -qq apache2
        elif command -v dnf > /dev/null 2>&1; then
            dnf install -y httpd
        elif command -v yum > /dev/null 2>&1; then
            yum install -y httpd
        elif command -v pacman > /dev/null 2>&1; then
            pacman -S --noconfirm apache
        else
            echo "  [!] Unknown package manager — install manually"
        fi

        # Determine service name
        if command -v apache2 > /dev/null 2>&1 || dpkg -l apache2 2>/dev/null | grep -q "^ii"; then
            WEB_INSTALLED=true
            WEB_NAME="apache2"
        elif command -v httpd > /dev/null 2>&1 || rpm -q httpd >/dev/null 2>&1; then
            WEB_INSTALLED=true
            WEB_NAME="httpd"
        fi

        if [ "$WEB_INSTALLED" = true ]; then
            echo "  [OK] Installed"
            printf "  Start $WEB_NAME now? [y/n]: "
            read -r answer2
            if [ "$answer2" = "y" ] || [ "$answer2" = "Y" ]; then
                systemctl enable "$WEB_NAME" 2>/dev/null
                systemctl start "$WEB_NAME" 2>/dev/null
                WEB_RUNNING=true
                echo "  [OK] $WEB_NAME started"
            fi
        else
            echo "  [!] Installation failed"
        fi
    else
        echo "  [SKIP] Not installing web server"
        echo "  To install manually:"
        echo "    sudo apt install apache2"
        echo "    sudo systemctl start apache2"
        ISSUES=$((ISSUES + 1))
    fi
fi
echo ""

# ==================================================================
# Step 4: Check FTP Server (needed for FTP Brute Force attack)
# ==================================================================
echo "Step 4: Checking FTP Server (needed for FTP Brute Force attack)..."
echo ""

FTP_INSTALLED=false
FTP_RUNNING=false

if dpkg -l vsftpd 2>/dev/null | grep -q "^ii"; then
    FTP_INSTALLED=true
    FTP_NAME="vsftpd"
    echo "  [OK] vsftpd is installed"
elif rpm -q vsftpd >/dev/null 2>&1; then
    FTP_INSTALLED=true
    FTP_NAME="vsftpd"
    echo "  [OK] vsftpd is installed"
fi

if [ "$FTP_INSTALLED" = true ]; then
    if systemctl is-active --quiet "$FTP_NAME" 2>/dev/null; then
        FTP_RUNNING=true
        echo "  [OK] $FTP_NAME service is running"
    else
        echo "  [!] $FTP_NAME is installed but NOT running"
        echo ""
        printf "  Do you want to start $FTP_NAME? [y/n]: "
        read -r answer
        if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            systemctl enable "$FTP_NAME" 2>/dev/null
            systemctl start "$FTP_NAME" 2>/dev/null
            if systemctl is-active --quiet "$FTP_NAME" 2>/dev/null; then
                FTP_RUNNING=true
                echo "  [OK] $FTP_NAME started"
            else
                echo "  [!] Failed to start $FTP_NAME"
            fi
        else
            echo "  [SKIP] $FTP_NAME not started"
            echo "  To start it manually:"
            echo "    sudo systemctl start $FTP_NAME"
        fi
    fi
else
    echo "  [!] vsftpd FTP server NOT installed"
    echo "      FTP server is needed for the FTP Brute Force attack."
    echo "      (CICIDS2018 used Patator against FTP on Feb 14)"
    echo ""
    printf "  Do you want to install vsftpd? [y/n]: "
    read -r answer
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        echo "  Installing vsftpd..."
        if command -v apt-get > /dev/null 2>&1; then
            apt-get update -qq
            apt-get install -y -qq vsftpd
        elif command -v dnf > /dev/null 2>&1; then
            dnf install -y vsftpd
        elif command -v yum > /dev/null 2>&1; then
            yum install -y vsftpd
        elif command -v pacman > /dev/null 2>&1; then
            pacman -S --noconfirm vsftpd
        else
            echo "  [!] Unknown package manager — install manually"
        fi

        if command -v vsftpd > /dev/null 2>&1 || dpkg -l vsftpd 2>/dev/null | grep -q "^ii"; then
            FTP_INSTALLED=true
            FTP_NAME="vsftpd"
            echo "  [OK] Installed"
            printf "  Start vsftpd now? [y/n]: "
            read -r answer2
            if [ "$answer2" = "y" ] || [ "$answer2" = "Y" ]; then
                systemctl enable vsftpd 2>/dev/null
                systemctl start vsftpd 2>/dev/null
                FTP_RUNNING=true
                echo "  [OK] vsftpd started"
            fi
        else
            echo "  [!] Installation failed"
        fi
    else
        echo "  [SKIP] Not installing FTP server"
        echo "  To install manually:"
        echo "    sudo apt install vsftpd"
        echo "    sudo systemctl start vsftpd"
        echo "  Note: FTP brute force attack will still work against SSH (--ssh)"
    fi
fi
echo ""

# ==================================================================
# Step 5: Check network tools
# ==================================================================
echo "Step 5: Checking network tools..."
echo ""

if command -v ifconfig > /dev/null 2>&1; then
    echo "  [OK] net-tools installed"
else
    echo "  [!] net-tools not installed (optional — for ifconfig)"
    echo "      To install: sudo apt install net-tools"
fi
echo ""

# ==================================================================
# Step 6: Check libpcap
# ==================================================================
echo "Step 6: Checking libpcap (needed by NIDS for packet capture)..."
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
# Step 7: Check NIDS project
# ==================================================================
echo "Step 7: Checking NIDS project..."
echo ""

# When run with sudo, $HOME is /root. Get original user's home too.
REAL_HOME="$HOME"
if [ -n "$SUDO_USER" ]; then
    REAL_HOME=$(eval echo "~$SUDO_USER")
fi

# Also check the script's own parent directory
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
SCRIPT_PARENT="$(dirname "$SCRIPT_DIR" 2>/dev/null)"

NIDS_DIR=""
for _d in \
    "$SCRIPT_PARENT" \
    "$REAL_HOME/Nids" \
    "$REAL_HOME/nids" \
    "$REAL_HOME/NIDS" \
    "$REAL_HOME/Nids-Network-Intrusion-Detection-System" \
    "$REAL_HOME/nids-network-intrusion-detection-system" \
    "$REAL_HOME/Desktop/Nids" \
    "$REAL_HOME/Desktop/Nids-Network-Intrusion-Detection-System" \
    "$HOME/Nids" \
    "$HOME/nids" \
    "$HOME/NIDS" \
    "$HOME/Nids-Network-Intrusion-Detection-System"; do
    if [ -d "$_d" ] && [ -f "$_d/classification.py" ]; then
        NIDS_DIR="$_d"
        break
    fi
done

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
# Step 8: Check packet capture permissions
# ==================================================================
echo "Step 8: Checking packet capture permissions..."
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
    echo "  ALL CHECKS PASSED — Device is ready for attacks!"
else
    echo "  CHECKS DONE — $ISSUES issue(s) found (see above)"
fi
echo "================================================================================"
echo ""

if [ -n "$DEVICE_IP" ]; then
    echo "  Your device IP: $DEVICE_IP"
else
    echo "  Your device IP: run 'ip addr show' to find it"
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
echo "  Required services for attacks:"
echo "    Web server (Apache)  - port 80  -> DoS (Hulk, Slowloris, GoldenEye) + DDoS (LOIC, HOIC)"
echo "    SSH server            - port 22  -> Brute Force SSH"
echo "    FTP server (vsftpd)  - port 21  -> Brute Force FTP"
echo ""
echo "  Then from your attacker machine:"
if [ -n "$DEVICE_IP" ]; then
    echo "    python run_all_attacks.py $DEVICE_IP"
else
    echo "    python run_all_attacks.py <DEVICE_IP>"
fi
echo ""
echo "================================================================================"
echo ""
