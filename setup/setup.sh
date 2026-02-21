#!/bin/sh
# Setup script for NIDS Project on Linux
# Checks prerequisites, creates venv, installs deps, builds CICFlowMeter, tests interface detection
# POSIX-compatible — works with sh (dash), bash, zsh, etc.

set -e  # Exit on error

# Navigate to project root (one level up from setup/)
cd "$(dirname "$0")/.." || exit 1
PROJECT_ROOT=$(pwd)

echo ""
echo "================================================================================"
echo "NIDS Project Setup - Linux"
echo "================================================================================"
echo ""

# ==================================================================
# Step 1: Check Python & Java (user must install these themselves)
# ==================================================================
echo "Step 1: Checking required software..."
echo ""

FAIL=false

# --- Python ---
if command -v python3 > /dev/null 2>&1; then
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    echo "  [OK] Python $python_version"

    # Check for venv module (separate package on Debian/Ubuntu)
    if ! python3 -c "import ensurepip" > /dev/null 2>&1; then
        echo "  [ERROR] Python 'venv' module is not installed."
        echo "          On Debian/Ubuntu, venv is a separate package."
        echo ""
        echo "    Run this command (copy-paste the WHOLE line, no spaces between python3):"
        echo ""
        echo "      sudo apt install python3-venv"
        echo ""
        echo "    If that doesn't work, try the version-specific package:"
        echo ""
        echo "      sudo apt install python${python_version%.*}-venv"
        echo ""
        echo "    Other distros (venv is already included, just reinstall python):"
        echo "      Fedora/RHEL:  sudo dnf install python3"
        echo "      Arch Linux:   sudo pacman -S python"
        echo ""
        FAIL=true
    fi
else
    echo "  [ERROR] Python3 is not installed."
    echo ""
    echo "    Install it yourself:"
    echo "      Ubuntu/Debian:  sudo apt install python3 python3-venv python3-dev"
    echo "      Fedora/RHEL:    sudo dnf install python3 python3-devel"
    echo "      Arch Linux:     sudo pacman -S python"
    echo "      Other:          https://www.python.org/downloads/"
    echo ""
    FAIL=true
fi

# --- Java ---
JAVA_OK=false
if command -v java > /dev/null 2>&1; then
    java_version_full=$(java -version 2>&1 | head -1)
    JAVA_MAJOR=$(java -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+)(\.[0-9]+)*.*/\1/')
    if [ "$JAVA_MAJOR" = "1" ]; then
        JAVA_MAJOR=$(java -version 2>&1 | head -1 | sed -E 's/.*"1\.([0-9]+).*/\1/')
    fi

    if [ "$JAVA_MAJOR" -ge 8 ] 2>/dev/null && [ "$JAVA_MAJOR" -le 21 ] 2>/dev/null; then
        echo "  [OK] Java $JAVA_MAJOR ($java_version_full)"
        JAVA_OK=true
    else
        echo "  [ERROR] Java $JAVA_MAJOR is NOT compatible. Need Java 8-21."
        echo ""
        echo "    You need the Java Development Kit (JDK), version 8 to 21."
        echo "    Copy-paste the install command for your distro:"
        echo ""
        echo "      Ubuntu/Debian:  sudo apt install openjdk-17-jdk"
        echo "      Fedora/RHEL:    sudo dnf install java-17-openjdk-devel"
        echo "      Arch Linux:     sudo pacman -S jdk17-openjdk"
        if command -v archlinux-java > /dev/null 2>&1; then
            echo "      Then switch:    sudo archlinux-java set java-17-openjdk"
        fi
        echo "      Other distro:   https://adoptium.net/ (Temurin 17 LTS)"
        echo ""
        FAIL=true
    fi

    # Check for javac (JDK vs JRE) — Gradle needs the compiler
    if [ "$JAVA_OK" = true ]; then
        if ! command -v javac > /dev/null 2>&1; then
            echo "  [ERROR] 'javac' (Java compiler) not found."
            echo "          You have Java installed, but only the runtime (JRE)."
            echo "          Gradle needs the full JDK which includes javac."
            echo ""
            echo "    NOTE: Do NOT search for 'javac' — it is included in the JDK package."
            echo ""
            echo "    Copy-paste the install command for your distro:"
            echo ""
            echo "      Ubuntu/Debian:  sudo apt install openjdk-17-jdk"
            echo "      Fedora/RHEL:    sudo dnf install java-17-openjdk-devel"
            echo "      Arch Linux:     sudo pacman -S jdk${JAVA_MAJOR}-openjdk"
            if command -v archlinux-java > /dev/null 2>&1; then
                echo "      Then switch:    sudo archlinux-java set java-${JAVA_MAJOR}-openjdk"
                echo ""
                echo "      (Check available versions with: archlinux-java status)"
                if archlinux-java status 2>/dev/null | grep -q "jdk"; then
                    echo ""
                    echo "    Your installed Java environments:"
                    archlinux-java status 2>/dev/null | while read -r line; do
                        echo "      $line"
                    done
                fi
            fi
            echo "      Other distro:   https://adoptium.net/ (Temurin 17 LTS)"
            echo ""
            FAIL=true
            JAVA_OK=false
        else
            echo "  [OK] javac found (JDK)"
        fi
    fi
else
    echo "  [ERROR] Java is not installed."
    echo ""
    echo "    You need the Java Development Kit (JDK), version 8 to 21."
    echo "    Copy-paste the install command for your distro:"
    echo ""
    echo "      Ubuntu/Debian:  sudo apt install openjdk-17-jdk"
    echo "      Fedora/RHEL:    sudo dnf install java-17-openjdk-devel"
    echo "      Arch Linux:     sudo pacman -S jdk17-openjdk"
    if command -v archlinux-java > /dev/null 2>&1 || command -v pacman > /dev/null 2>&1; then
        echo "      Then switch:    sudo archlinux-java set java-17-openjdk"
    fi
    echo "      Other distro:   https://adoptium.net/ (Temurin 17 LTS)"
    echo ""
    FAIL=true
fi

# --- libpcap (needed by jnetpcap native library) ---
LIBPCAP_FOUND=false
if ldconfig -p 2>/dev/null | grep -q libpcap; then
    LIBPCAP_FOUND=true
elif [ -f /usr/lib/x86_64-linux-gnu/libpcap.so ] || \
     [ -f /usr/lib/x86_64-linux-gnu/libpcap.so.1 ] || \
     [ -f /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 ] || \
     [ -f /usr/lib/libpcap.so ] || \
     [ -f /usr/lib/libpcap.so.1 ]; then
    LIBPCAP_FOUND=true
fi

if [ "$LIBPCAP_FOUND" = true ]; then
    echo "  [OK] libpcap found"
else
    echo "  [ERROR] libpcap is not installed."
    echo "          jnetpcap (packet capture library) needs libpcap to work."
    echo ""
    echo "    Copy-paste the install command for your distro:"
    echo ""
    echo "      Ubuntu/Debian:  sudo apt install libpcap-dev"
    echo "      Fedora/RHEL:    sudo dnf install libpcap-devel"
    echo "      Arch Linux:     sudo pacman -S libpcap"
    echo ""
    FAIL=true
fi

if [ "$FAIL" = true ]; then
    echo "================================================================================"
    echo "  SETUP CANNOT CONTINUE"
    echo "  Install the missing software above, then re-run this script."
    echo "================================================================================"
    exit 1
fi

# ==================================================================
# Step 2: Create virtual environment
# ==================================================================
echo ""
echo "Step 2: Creating virtual environment..."
echo ""

if [ -d "venv" ]; then
    echo "  [OK] Already exists — skipping"
else
    if ! python3 -m venv venv 2>&1; then
        echo ""
        echo "  [ERROR] Failed to create virtual environment."
        echo ""
        echo "    Most likely cause: the python3-venv package is not installed."
        echo "    Fix:"
        echo "      Ubuntu/Debian:  sudo apt install python3-venv"
        echo "      Then re-run this script."
        echo ""
        exit 1
    fi
    if [ ! -d "venv" ]; then
        echo "  [ERROR] venv directory was not created"
        exit 1
    fi
    echo "  [OK] Virtual environment created"
fi

# ==================================================================
# Step 3: Activate venv & install pip dependencies
# ==================================================================
echo ""
echo "Step 3: Installing Python dependencies..."
echo ""

. venv/bin/activate

pip install --upgrade pip --quiet
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "  [ERROR] pip install failed"
    exit 1
fi
echo "  [OK] Dependencies installed"

# ==================================================================
# Step 4: Build CICFlowMeter
# ==================================================================
echo ""
echo "Step 4: Building CICFlowMeter..."
echo ""

if [ ! -f "CICFlowMeter/gradlew" ]; then
    echo "  [ERROR] CICFlowMeter/gradlew not found"
    exit 1
fi

if [ -d "CICFlowMeter/build/classes/java/main" ]; then
    echo "  [OK] Already built — skipping"
else
    echo "  Building with Gradle (this may take a minute)..."
    cd CICFlowMeter
    chmod +x gradlew
    ./gradlew --no-daemon classes
    if [ $? -eq 0 ]; then
        echo "  [OK] CICFlowMeter built successfully"
    else
        echo "  [ERROR] Gradle build failed"
        echo "  Try manually: cd CICFlowMeter && ./gradlew classes"
        cd "$PROJECT_ROOT"
        exit 1
    fi
    cd "$PROJECT_ROOT"
fi

# ==================================================================
# Step 5: Test interface detection
# ==================================================================
echo ""
echo "Step 5: Testing network interface detection..."
echo ""

# Run the Java interface listing through Gradle
# Disable set -e here — this command may fail due to permissions, which is expected
set +e
INTERFACE_OUTPUT=$(cd CICFlowMeter && chmod +x gradlew && ./gradlew --no-daemon exeLive '--args=--list-interfaces' 2>&1)
set -e
INTERFACE_COUNT=$(echo "$INTERFACE_OUTPUT" | grep -cE '^[0-9]+\|' || true)

if [ "$INTERFACE_COUNT" -gt 0 ] 2>/dev/null; then
    echo "  [OK] Detected $INTERFACE_COUNT network interface(s):"
    echo ""
    echo "$INTERFACE_OUTPUT" | grep -E '^[0-9]+\|' | while IFS='|' read -r idx name desc addrs; do
        if [ "$desc" = "N/A" ] || [ -z "$desc" ]; then
            echo "        $idx. $name  ($addrs)"
        else
            echo "        $idx. $desc  ($addrs)"
        fi
    done
    echo ""
else
    echo "  [WARNING] No network interfaces detected on first try."
    echo ""

    # Check architecture (fatal — nothing else will help)
    ARCH=$(uname -m)
    if [ "$ARCH" != "x86_64" ]; then
        echo "  [ERROR] Your architecture is $ARCH. The bundled jnetpcap native"
        echo "    library is compiled for x86_64 only. This won't work on ARM/other."
        echo ""
        echo "  Fix the issue above, then re-run this script."
        exit 1
    fi

    # Check if libpcap is missing
    LIBPCAP_MISSING=false
    if ! ldconfig -p 2>/dev/null | grep -q libpcap && \
       [ ! -f /usr/lib/x86_64-linux-gnu/libpcap.so ] && \
       [ ! -f /usr/lib/x86_64-linux-gnu/libpcap.so.1 ] && \
       [ ! -f /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 ] && \
       [ ! -f /usr/lib/libpcap.so ] && \
       [ ! -f /usr/lib/libpcap.so.1 ]; then
        LIBPCAP_MISSING=true
        echo "  [ERROR] libpcap is not installed."
        echo "    Fix:"
        echo "      Ubuntu/Debian:  sudo apt install libpcap-dev"
        echo "      Fedora/RHEL:    sudo dnf install libpcap-devel"
        echo "      Arch Linux:     sudo pacman -S libpcap"
        echo ""
        echo "  Install libpcap, then re-run this script."
        exit 1
    fi

    # libpcap is installed — this is a permissions issue
    # Automatically fix by granting Java packet capture capabilities
    JAVA_PATH=$(readlink -f "$(which java)")
    echo "  libpcap is installed. Java needs permission to capture packets."
    echo ""
    echo "  Granting Java packet capture capability (requires sudo)..."
    echo "    Running: sudo setcap cap_net_raw,cap_net_admin=eip $JAVA_PATH"
    echo ""

    set +e
    sudo setcap cap_net_raw,cap_net_admin=eip "$JAVA_PATH"
    SETCAP_RESULT=$?
    set -e

    if [ "$SETCAP_RESULT" -ne 0 ]; then
        echo ""
        echo "  [ERROR] Failed to set capabilities. You can try manually:"
        echo "      sudo setcap cap_net_raw,cap_net_admin=eip $JAVA_PATH"
        echo ""
        echo "    Or run the program with sudo each time:"
        echo "      sudo $(pwd)/venv/bin/python classification.py"
        echo ""
        exit 1
    fi

    echo "  [OK] Permissions granted. Retrying interface detection..."
    echo ""

    # Retry interface detection
    set +e
    INTERFACE_OUTPUT=$(cd CICFlowMeter && ./gradlew --no-daemon exeLive '--args=--list-interfaces' 2>&1)
    set -e
    INTERFACE_COUNT=$(echo "$INTERFACE_OUTPUT" | grep -cE '^[0-9]+\|' || true)

    if [ "$INTERFACE_COUNT" -gt 0 ] 2>/dev/null; then
        echo "  [OK] Detected $INTERFACE_COUNT network interface(s):"
        echo ""
        echo "$INTERFACE_OUTPUT" | grep -E '^[0-9]+\|' | while IFS='|' read -r idx name desc addrs; do
            if [ "$desc" = "N/A" ] || [ -z "$desc" ]; then
                echo "        $idx. $name  ($addrs)"
            else
                echo "        $idx. $desc  ($addrs)"
            fi
        done
        echo ""
    else
        echo "  [ERROR] Still no interfaces detected after granting permissions."
        echo ""

        # Show raw Java errors for debugging
        ERR_LINES=$(echo "$INTERFACE_OUTPUT" | grep -iE 'error|exception|denied|libpcap|unsatisfied' | head -5)
        if [ -n "$ERR_LINES" ]; then
            echo "  Java errors (for debugging):"
            echo "$ERR_LINES" | while read -r line; do
                echo "    $line"
            done
            echo ""
        fi

        echo "  Try running with sudo instead:"
        echo "      sudo $(pwd)/venv/bin/python classification.py"
        echo ""
        exit 1
    fi
fi

# ==================================================================
# Done
# ==================================================================
echo "================================================================================"
echo "  Setup Complete!  Everything is working."
echo "================================================================================"
echo ""
echo "  IMPORTANT: You must activate the virtual environment before running."
echo ""

case "$0" in
    *setup.sh*)
        echo "  You ran this script with 'sh' or 'bash', so the venv is NOT active."
        echo "  Activate it now:"
        echo ""
        echo "      source venv/bin/activate    (bash/zsh)"
        echo "      . venv/bin/activate          (any shell)"
        echo ""
        ;;
    *)
        echo "  venv is active. You're ready to go."
        echo ""
        ;;
esac

echo "  Run live classification:"
echo "      python classification.py --duration 180"
echo ""
echo "  Or with sudo (needed if you haven't set Java capabilities):"
echo "      sudo $(pwd)/venv/bin/python classification.py --duration 180"
echo ""
echo "  Run ML model pipeline:"
echo "      python ml_model.py --help"
echo ""
echo "================================================================================"
echo ""
