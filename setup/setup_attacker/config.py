"""
Device Attack Configuration
Stores IP ranges, ports, and attack defaults
"""

# Currently Detected VM (populated by discover_and_save.py)
TARGET_VM_IP = "192.168.56.104"
DETECTED_PORTS = [22, 80, 21]

# IP ranges to scan for VMs (CIDR or single range)
IP_RANGES = [
    "192.168.56.0/24",    # VirtualBox Host-Only Adapter
    "10.0.2.0/24",        # VirtualBox NAT Adapter
    "192.168.1.0/24",     # Common home network
    "172.16.0.0/12",      # Private network range
]

# Service ports on target VM
PORTS = {
    "web": 80,            # HTTP (DoS/DDoS target)
    "ssh": 22,            # SSH (Brute Force target)
    "ftp": 21,            # FTP (Brute Force target)
}

# Default attack settings
DEFAULTS = {
    "duration": 120,      # seconds
    "attack_type": "default",  # "default" (5 attacks) or "all" (6 attacks)
    "shuffle": True,      # Shuffle attack order
}

# Attack types
ATTACK_TYPES = {
    "dos": "HTTP DoS attack",
    "ddos": "Distributed DoS attack",
    "brute_force": "SSH/FTP Brute Force",
    "botnet": "Botnet C2 beaconing",
    "infiltration": "Port scanning / Infiltration",
}

# Attack descriptions
ATTACK_DESCRIPTIONS = {
    "dos": "HTTP-layer DoS (Hulk, Slowloris, GoldenEye, SlowHTTP)",
    "ddos": "Multi-threaded DDoS (LOIC-HTTP, LOIC-UDP, HOIC)",
    "brute_force": "SSH and FTP credential brute force attacks",
    "botnet": "Ares/Zeus C2 beaconing, exfiltration, keylog simulation",
    "infiltration": "Nmap-style port scanning",
}
