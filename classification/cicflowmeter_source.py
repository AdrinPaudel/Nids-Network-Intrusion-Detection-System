"""
CICFlowMeter Live Source
Starts CICFlowMeter's LiveCapture Java process, reads flow CSV lines from stdout,
and pushes them into the preprocessor queue.
"""

import os
import sys
import subprocess
import threading
import queue
import csv
import io
import time
import signal
import platform

# Windows-specific subprocess flags to prevent console window popups
_IS_WINDOWS = sys.platform.startswith('win')
_SUBPROCESS_FLAGS = {}
if _IS_WINDOWS:
    _SUBPROCESS_FLAGS['creationflags'] = (
        subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    )

# Add project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_IDENTIFIER_COLUMNS, CLASSIFICATION_WIFI_KEYWORDS,
    CLASSIFICATION_EXCLUDE_KEYWORDS,
    CLASSIFICATION_SUBPROCESS_TIMEOUT_LIST,
    CLASSIFICATION_SUBPROCESS_TIMEOUT_MAIN,
    CLASSIFICATION_SUBPROCESS_TIMEOUT_FORCE,
    CLASSIFICATION_SUBPROCESS_TIMEOUT_JOIN,
    COLOR_CYAN, COLOR_RED, COLOR_GREEN, COLOR_YELLOW,
    COLOR_BLUE, COLOR_DARK_GRAY, COLOR_RESET
)

# Keep backward compatibility
IDENTIFIER_COLUMNS = CLASSIFICATION_IDENTIFIER_COLUMNS


# ============================================================
# CICFlowMeter column name → Training data column name mapping
# CICFlowMeter's FlowFeature.java uses different names than
# the CICIDS2018 CSV files the model was trained on.
# ============================================================
CICFLOWMETER_TO_TRAINING_COLUMNS = {
    "Flow ID": "Flow ID",
    "Src IP": "Src IP",
    "Src Port": "Src Port",
    "Dst IP": "Dst IP",
    "Dst Port": "Dst Port",
    "Protocol": "Protocol",
    "Timestamp": "Timestamp",
    "Flow Duration": "Flow Duration",
    "Total Fwd Packet": "Tot Fwd Pkts",
    "Total Bwd packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packet": "TotLen Fwd Pkts",
    "Total Length of Bwd Packet": "TotLen Bwd Pkts",
    "Fwd Packet Length Max": "Fwd Pkt Len Max",
    "Fwd Packet Length Min": "Fwd Pkt Len Min",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean",
    "Fwd Packet Length Std": "Fwd Pkt Len Std",
    "Bwd Packet Length Max": "Bwd Pkt Len Max",
    "Bwd Packet Length Min": "Bwd Pkt Len Min",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
    "Bwd Packet Length Std": "Bwd Pkt Len Std",
    "Flow Bytes/s": "Flow Byts/s",
    "Flow Packets/s": "Flow Pkts/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Total": "Fwd IAT Tot",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Total": "Bwd IAT Tot",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Length": "Fwd Header Len",
    "Bwd Header Length": "Bwd Header Len",
    "Fwd Packets/s": "Fwd Pkts/s",
    "Bwd Packets/s": "Bwd Pkts/s",
    "Packet Length Min": "Pkt Len Min",
    "Packet Length Max": "Pkt Len Max",
    "Packet Length Mean": "Pkt Len Mean",
    "Packet Length Std": "Pkt Len Std",
    "Packet Length Variance": "Pkt Len Var",
    "FIN Flag Count": "FIN Flag Cnt",
    "SYN Flag Count": "SYN Flag Cnt",
    "RST Flag Count": "RST Flag Cnt",
    "PSH Flag Count": "PSH Flag Cnt",
    "ACK Flag Count": "ACK Flag Cnt",
    "URG Flag Count": "URG Flag Cnt",
    "CWR Flag Count": "CWE Flag Count",
    "ECE Flag Count": "ECE Flag Cnt",
    "Down/Up Ratio": "Down/Up Ratio",
    "Average Packet Size": "Pkt Size Avg",
    "Fwd Segment Size Avg": "Fwd Seg Size Avg",
    "Bwd Segment Size Avg": "Bwd Seg Size Avg",
    "Fwd Bytes/Bulk Avg": "Fwd Byts/b Avg",
    "Fwd Packet/Bulk Avg": "Fwd Pkts/b Avg",
    "Fwd Bulk Rate Avg": "Fwd Blk Rate Avg",
    "Bwd Bytes/Bulk Avg": "Bwd Byts/b Avg",
    "Bwd Packet/Bulk Avg": "Bwd Pkts/b Avg",
    "Bwd Bulk Rate Avg": "Bwd Blk Rate Avg",
    "Subflow Fwd Packets": "Subflow Fwd Pkts",
    "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Subflow Bwd Packets": "Subflow Bwd Pkts",
    "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "FWD Init Win Bytes": "Init Fwd Win Byts",
    "Bwd Init Win Bytes": "Init Bwd Win Byts",
    "Fwd Act Data Pkts": "Fwd Act Data Pkts",
    "Fwd Seg Size Min": "Fwd Seg Size Min",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
    "Label": "Label",
}

# Identifier columns to preserve for threat reporting (uses config import above)


def list_interfaces():
    """
    List available network interfaces by calling CICFlowMeter's LiveCapture.
    Returns list of dicts with keys: index, name, description, addresses
    """
    cicflowmeter_dir = os.path.join(PROJECT_ROOT, "CICFlowMeter")
    if sys.platform.startswith("win"):
        gradlew = os.path.join(cicflowmeter_dir, "gradlew.bat")
    else:
        gradlew = os.path.join(cicflowmeter_dir, "gradlew")

    try:
        result = subprocess.run(
            [gradlew, "--no-daemon", "exeLive", '--args=--list-interfaces'],
            cwd=cicflowmeter_dir,
            capture_output=True,
            text=True,
            timeout=CLASSIFICATION_SUBPROCESS_TIMEOUT_LIST,
            **_SUBPROCESS_FLAGS
        )

        interfaces = []
        output = result.stdout + result.stderr
        for line in output.splitlines():
            line = line.strip()
            # Parse lines like: 0|NAME|DESCRIPTION|ADDRESSES
            parts = line.split("|")
            if len(parts) == 4 and parts[0].isdigit():
                interfaces.append({
                    "index": int(parts[0]),
                    "name": parts[1],
                    "description": parts[2],
                    "addresses": parts[3],
                })
        return interfaces

    except Exception as e:
        print(f"\033[91m[ERROR] Failed to list interfaces: {e}\033[0m")
        return []


def select_wifi_interface(interfaces):
    """
    Auto-select the WiFi adapter from the list of interfaces.
    Looks for keywords: Wi-Fi, WiFi, Wireless, WLAN
    Returns the interface dict or None.
    """
    # Use config values for keywords
    wifi_keywords = CLASSIFICATION_WIFI_KEYWORDS
    exclude_keywords = CLASSIFICATION_EXCLUDE_KEYWORDS

    for iface in interfaces:
        desc_lower = iface["description"].lower()
        name_lower = iface["name"].lower()

        # Check if it matches WiFi keywords
        is_wifi = any(kw in desc_lower or kw in name_lower for kw in wifi_keywords)
        # Check it's not a virtual/excluded adapter
        is_excluded = any(kw in desc_lower for kw in exclude_keywords)

        if is_wifi and not is_excluded:
            return iface

    # Fallback: return any WiFi interface even if it has "virtual" in name
    for iface in interfaces:
        desc_lower = iface["description"].lower()
        is_wifi = any(kw in desc_lower for kw in wifi_keywords)
        is_virtual = "virtual" in desc_lower or "direct" in desc_lower
        if is_wifi and not is_virtual:
            return iface

    return None


def get_wifi_interfaces(interfaces):
    """
    Get all WiFi adapters from the list of interfaces.
    Returns list of interface dicts matching WiFi keywords.
    """
    wifi_keywords = CLASSIFICATION_WIFI_KEYWORDS
    exclude_keywords = CLASSIFICATION_EXCLUDE_KEYWORDS
    wifi_list = []

    for iface in interfaces:
        desc_lower = iface["description"].lower()
        name_lower = iface["name"].lower()

        # Check if it matches WiFi keywords
        is_wifi = any(kw in desc_lower or kw in name_lower for kw in wifi_keywords)
        # Check it's not a virtual/excluded adapter
        is_excluded = any(kw in desc_lower for kw in exclude_keywords)

        if is_wifi and not is_excluded:
            wifi_list.append(iface)

    return wifi_list


def get_ethernet_interfaces(interfaces):
    """
    Get all Ethernet adapters from the list of interfaces.
    Returns list of interface dicts matching Ethernet keywords.
    """
    wifi_keywords = CLASSIFICATION_WIFI_KEYWORDS
    exclude_keywords = CLASSIFICATION_EXCLUDE_KEYWORDS
    ethernet_list = []

    for iface in interfaces:
        desc_lower = iface["description"].lower()
        name_lower = iface["name"].lower()

        # Check if it's NOT a WiFi adapter
        is_wifi = any(kw in desc_lower or kw in name_lower for kw in wifi_keywords)
        # Check it's not a virtual/excluded adapter
        is_excluded = any(kw in desc_lower for kw in exclude_keywords)

        if not is_wifi and not is_excluded:
            ethernet_list.append(iface)

    return ethernet_list


class CICFlowMeterSource:
    """
    Manages the CICFlowMeter LiveCapture subprocess.
    Reads CSV flow lines from Java stdout and pushes them to the flow_queue.
    """

    def __init__(self, flow_queue, interface_name=None, stop_event=None):
        """
        Args:
            flow_queue: queue.Queue to push parsed flow dicts into
            interface_name: network interface device name (auto-detect WiFi if None)
            stop_event: threading.Event (not used internally; source has its own)
        """
        self.flow_queue = flow_queue
        self.interface_name = interface_name
        # Source uses its own internal stop event, NOT the shared session one
        self._stop_event = threading.Event()
        self.process = None
        self.header = None
        self.flow_count = 0
        self._reader_thread = None
        self._header_received = threading.Event()   # Set when CSV header is detected
        self._java_ready = threading.Event()         # Set when Java reports READY
        self._packet_count = 0                       # Packets reported by Java SCAN messages

    def start(self):
        """Start the CICFlowMeter capture process."""
        # Use interface_name if provided, otherwise no auto-detection
        # (detection happens at the classification.py level now)
        if self.interface_name is None:
            print(f"{COLOR_RED}[CICFLOWMETER] No interface specified!{COLOR_RESET}")
            return False

        # Set up paths
        cicflowmeter_dir = os.path.join(PROJECT_ROOT, "CICFlowMeter")
        
        # Determine platform-specific jnetpcap paths
        if sys.platform.startswith("win"):
            platform_dir = "win"
            gradlew = os.path.join(cicflowmeter_dir, "gradlew.bat")
        else:
            platform_dir = "linux"
            gradlew = os.path.join(cicflowmeter_dir, "gradlew")
        
        lib_path = os.path.join(cicflowmeter_dir, "jnetpcap", platform_dir, "jnetpcap-1.4.r1425")

        # Stop any lingering Gradle daemons from previous runs that might
        # hold pcap handles open and prevent new captures from seeing traffic.
        try:
            subprocess.run(
                [gradlew, "--stop"],
                capture_output=True, timeout=10, cwd=cicflowmeter_dir,
                **_SUBPROCESS_FLAGS,
            )
        except Exception:
            pass

        # Kill zombie Java/CICFlowMeter processes from previous runs.
        # If a previous capture didn't clean up properly, the old java.exe
        # may still hold the pcap handle open, causing the NEW capture to
        # receive 0 packets (Npcap won't deliver to two handles reliably).
        self._kill_zombie_java_processes()
        
        # CRITICAL: After killing zombies, wait for Npcap to fully release the handle.
        # Some drivers take time to release resources, especially after a forced kill.
        # Without this wait, the new capture may still see 0 packets.
        print(f"{COLOR_CYAN}[CICFLOWMETER] Waiting for Npcap handle release (5s)...{COLOR_RESET}")
        time.sleep(5)

        # Build command to run capture
        cmd = [
            gradlew,
            "--no-daemon",
            "exeLive",
            f"--args=--live {self.interface_name}"
        ]

        print(f"{COLOR_CYAN}[CICFLOWMETER] Starting capture on: {self.interface_name}{COLOR_RESET}")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,  # Need stdin to send STOP command
                text=True,
                bufsize=1,  # Line buffered
                cwd=cicflowmeter_dir,
                env={**os.environ, f"JAVA_LIBRARY_PATH": lib_path},
                **_SUBPROCESS_FLAGS,
            )
        except Exception as e:
            print(f"{COLOR_RED}[CICFLOWMETER] Failed to start: {e}{COLOR_RESET}")
            return False

        # Start stderr reader thread (for logging)
        self._stderr_thread = threading.Thread(
            target=self._read_stderr, daemon=True, name="cicflowmeter-stderr"
        )
        self._stderr_thread.start()

        # Start stdout reader thread (for flow data)
        self._reader_thread = threading.Thread(
            target=self._read_flows, daemon=True, name="cicflowmeter-stdout"
        )
        self._reader_thread.start()

        # Health check: wait for Java to become ready and header to be detected
        print(f"{COLOR_CYAN}[CICFLOWMETER] Waiting for Java process to initialize...{COLOR_RESET}")
        
        # Wait up to 60 seconds for the header (Gradle build may take time)
        header_timeout = 60
        if self._header_received.wait(timeout=header_timeout):
            print(f"{COLOR_GREEN}[CICFLOWMETER] Java initialized. Verify capture is working...{COLOR_RESET}")
            return True
        else:
            # Check if process is still alive
            if self.process.poll() is not None:
                print(f"{COLOR_RED}[CICFLOWMETER] ERROR: Java process exited prematurely (code={self.process.returncode}){COLOR_RESET}")
                return False
            else:
                print(f"{COLOR_YELLOW}[CICFLOWMETER] WARNING: Header not detected within {header_timeout}s (continuing anyway...){COLOR_RESET}")
                return True

    def _read_stderr(self):
        """Read and display CICFlowMeter stderr messages.
        Parses SCAN diagnostics for health monitoring."""
        try:
            while True:
                line = self.process.stderr.readline()
                if not line:
                    break  # EOF - process exited
                line = line.strip()
                if not line:
                    continue
                if "READY:" in line:
                    self._java_ready.set()
                    print(f"{COLOR_GREEN}[CICFLOWMETER] {line}{COLOR_RESET}")
                elif "ERROR:" in line:
                    print(f"{COLOR_RED}[CICFLOWMETER] {line}{COLOR_RESET}")
                elif "SCAN:" in line:
                    # Parse: SCAN: packets=N valid=N emitted=N active_flows=N
                    try:
                        parts = line.split("SCAN:")[1].strip().split()
                        for part in parts:
                            if part.startswith("packets="):
                                self._packet_count = int(part.split("=")[1])
                    except Exception:
                        pass
                    print(f"{COLOR_DARK_GRAY}[CICFLOWMETER] {line}{COLOR_RESET}")
                elif "INFO:" in line:
                    print(f"{COLOR_BLUE}[CICFLOWMETER] {line}{COLOR_RESET}")
                elif "DONE:" in line:
                    print(f"{COLOR_GREEN}[CICFLOWMETER] {line}{COLOR_RESET}")
                else:
                    print(f"{COLOR_DARK_GRAY}[CICFLOWMETER-LOG] {line}{COLOR_RESET}")
        except Exception:
            pass

    def _read_flows(self):
        """Read CSV flow lines from stdout and push to queue.
        Uses readline() for more reliable reading (avoids Python iterator buffering).
        Keeps reading until stdout is closed (process exits),
        even after stop_event is set, to capture remaining flows dumped by Java.
        """
        skipped_lines = 0
        try:
            while True:
                line = self.process.stdout.readline()
                if not line:
                    break  # EOF - process exited, stdout pipe closed
                line = line.strip()
                if not line:
                    continue

                # Detect the real CSV header from CICFlowMeter.
                # Gradle outputs build messages (e.g. "Starting a Gradle Daemon...",
                # "> Configure project :") to stdout BEFORE Java prints the CSV header.
                # We identify the real header by checking for known CICFlowMeter column names.
                if self.header is None:
                    cols = line.split(",")
                    col_names = [c.strip() for c in cols]
                    # The real header contains "Flow ID" and "Src IP" (first two FlowFeature columns)
                    if "Flow ID" in col_names and "Src IP" in col_names:
                        self.header = [
                            CICFLOWMETER_TO_TRAINING_COLUMNS.get(c.strip(), c.strip())
                            for c in cols
                        ]
                        self._header_received.set()
                        print(f"{COLOR_CYAN}[CICFLOWMETER] CSV header detected ({len(self.header)} columns){COLOR_RESET}")
                        if skipped_lines > 0:
                            print(f"{COLOR_DARK_GRAY}[CICFLOWMETER] Skipped {skipped_lines} Gradle build lines before header{COLOR_RESET}")
                    else:
                        # Gradle build output — skip it
                        skipped_lines += 1
                        continue
                    continue

                # Parse CSV line into a dict
                try:
                    values = line.split(",")
                    if len(values) != len(self.header):
                        continue  # Skip malformed rows

                    flow_dict = dict(zip(self.header, values))

                    # Extract identifiers before they get dropped
                    identifiers = {}
                    for id_col in IDENTIFIER_COLUMNS:
                        mapped = CICFLOWMETER_TO_TRAINING_COLUMNS.get(id_col, id_col)
                        if mapped in flow_dict:
                            identifiers[id_col] = flow_dict[mapped]

                    flow_dict["__identifiers__"] = identifiers
                    self.flow_queue.put(flow_dict)
                    self.flow_count += 1

                    # Print first flow's details to verify parsing
                    if self.flow_count == 1:
                        print(f"{COLOR_CYAN}[CICFLOWMETER] First flow received! Src={identifiers.get('Src IP','?')} → "
                              f"Dst={identifiers.get('Dst IP','?')}:{identifiers.get('Dst Port','?')}{COLOR_RESET}")
                        print(f"{COLOR_CYAN}[DEBUG] Header ({len(self.header)} cols): {self.header[:7]}...{COLOR_RESET}")
                        print(f"{COLOR_CYAN}[DEBUG] Values ({len(values)} vals): {values[:7]}...{COLOR_RESET}")
                        print(f"{COLOR_CYAN}[DEBUG] Identifiers: {identifiers}{COLOR_RESET}")
                        print(f"{COLOR_CYAN}[DEBUG] Sample features: Dst Port={flow_dict.get('Dst Port','MISSING')}, "
                              f"Flow Duration={flow_dict.get('Flow Duration','MISSING')}, "
                              f"Tot Fwd Pkts={flow_dict.get('Tot Fwd Pkts','MISSING')}{COLOR_RESET}")
                    elif self.flow_count <= 5:
                        print(f"{COLOR_CYAN}[CICFLOWMETER] Flow #{self.flow_count}: "
                              f"Src={identifiers.get('Src IP','?')} → "
                              f"Dst={identifiers.get('Dst IP','?')}:{identifiers.get('Dst Port','?')}{COLOR_RESET}")

                except Exception as e:
                    print(f"{COLOR_YELLOW}[CICFLOWMETER] Parse error: {e}{COLOR_RESET}")
                    continue

        except Exception as e:
            if not self._stop_event.is_set():
                print(f"{COLOR_RED}[CICFLOWMETER] Reader error: {e}{COLOR_RESET}")

        print(f"{COLOR_CYAN}[CICFLOWMETER] Flow reader stopped. Total flows: {self.flow_count}{COLOR_RESET}")

    def _kill_zombie_java_processes(self):
        """Kill any lingering java.exe processes from previous CICFlowMeter runs.
        
        If a previous capture session didn't clean up properly (e.g., Ctrl+C, crash),
        the old java.exe may still hold the Npcap handle open on the interface.
        This causes new captures to receive 0 packets because Npcap doesn't
        reliably deliver packets to multiple handles on the same interface.
        """
        if not _IS_WINDOWS:
            return  # Only needed on Windows
        
        try:
            # Use WMIC to find java.exe processes with CICFlowMeter/LiveCapture in command line
            result = subprocess.run(
                ['wmic', 'process', 'where',
                 "name='java.exe' and (commandline like '%LiveCapture%' or commandline like '%CICFlowMeter%' or commandline like '%exeLive%')",
                 'get', 'processid,commandline', '/format:list'],
                capture_output=True, text=True, timeout=10,
                **_SUBPROCESS_FLAGS,
            )
            
            # Parse PIDs from WMIC output
            pids_to_kill = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("ProcessId="):
                    try:
                        pid = int(line.split("=")[1])
                        pids_to_kill.append(pid)
                    except (ValueError, IndexError):
                        pass
            
            if pids_to_kill:
                print(f"{COLOR_YELLOW}[CICFLOWMETER] Found {len(pids_to_kill)} zombie Java process(es): {pids_to_kill}{COLOR_RESET}")
                for pid in pids_to_kill:
                    try:
                        subprocess.run(
                            ['taskkill', '/F', '/T', '/PID', str(pid)],
                            capture_output=True, timeout=10,
                            **_SUBPROCESS_FLAGS,
                        )
                        print(f"{COLOR_YELLOW}[CICFLOWMETER] Killed zombie process PID={pid}{COLOR_RESET}")
                    except Exception:
                        pass
                # Brief pause to let Npcap release the handle
                time.sleep(2)
            else:
                print(f"{COLOR_DARK_GRAY}[CICFLOWMETER] No zombie Java processes found (good){COLOR_RESET}")
                
        except FileNotFoundError:
            # WMIC not available (deprecated in newer Windows), try PowerShell fallback
            try:
                ps_cmd = (
                    "Get-WmiObject Win32_Process -Filter \"name='java.exe'\" | "
                    "Where-Object { $_.CommandLine -like '*LiveCapture*' -or "
                    "$_.CommandLine -like '*CICFlowMeter*' -or "
                    "$_.CommandLine -like '*exeLive*' } | "
                    "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
                )
                subprocess.run(
                    ['powershell', '-NoProfile', '-Command', ps_cmd],
                    capture_output=True, timeout=15,
                    **_SUBPROCESS_FLAGS,
                )
            except Exception:
                pass
        except Exception as e:
            print(f"{COLOR_DARK_GRAY}[CICFLOWMETER] Zombie cleanup skipped: {e}{COLOR_RESET}")

    def stop(self):
        """Stop the CICFlowMeter capture process with immediate kill.
        First tries graceful shutdown, then forcefully terminates.
        """
        self._stop_event.set()

        if self.process:
            # Try graceful shutdown first (STOP command)
            try:
                try:
                    self.process.stdin.write("STOP\n")
                    self.process.stdin.flush()
                    self.process.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
                
                # Wait briefly for graceful exit
                try:
                    self.process.wait(timeout=5)  # Short timeout - 5 seconds max
                except subprocess.TimeoutExpired:
                    pass  # Will force kill below
            except Exception:
                pass

            # ALWAYS force kill - don't leave Java processes running
            if self.process.poll() is None:  # Still running?
                print(f"{COLOR_YELLOW}[CICFLOWMETER] Graceful shutdown didn't work, force killing...{COLOR_RESET}")
                self._force_kill()

            # Collect exit status to prevent ResourceWarning
            try:
                self.process.wait(timeout=3)
            except Exception:
                pass

            # Wait for reader thread to consume remaining flows
            if self._reader_thread and self._reader_thread.is_alive():
                self._reader_thread.join(timeout=CLASSIFICATION_SUBPROCESS_TIMEOUT_JOIN)
            
            # Close pipes
            self._close_pipes()
            
            print(f"{COLOR_GREEN}[CICFLOWMETER] Java process terminated. Total flows: {self.flow_count}{COLOR_RESET}")

    def _close_pipes(self):
        """Close all subprocess pipes to prevent resource warnings."""
        if self.process:
            try:
                if self.process.stdout and not self.process.stdout.closed:
                    self.process.stdout.close()
            except Exception:
                pass
            
            try:
                if self.process.stderr and not self.process.stderr.closed:
                    self.process.stderr.close()
            except Exception:
                pass
            
            try:
                if self.process.stdin and not self.process.stdin.closed:
                    self.process.stdin.close()
            except Exception:
                pass

    def _force_kill(self):
        """Force kill the subprocess and its children using taskkill."""
        if not self.process:
            return
        
        try:
            pid = self.process.pid
            poll_before = self.process.poll()
            
            if poll_before is not None:
                # Already dead
                return
            
            if _IS_WINDOWS:
                # Try to kill the process tree first (Gradle + Java children)
                try:
                    subprocess.run(
                        ['taskkill', '/F', '/T', '/PID', str(pid)],
                        capture_output=True, timeout=5
                    )
                    time.sleep(0.2)
                except Exception:
                    pass
                
                # Kill any remaining Java processes (may be orphaned children)
                try:
                    subprocess.run(
                        ['taskkill', '/F', '/IM', 'java.exe'],
                        capture_output=True, timeout=5
                    )
                    time.sleep(0.2)
                except Exception:
                    pass
                
                # Kill any remaining Gradle processes
                try:
                    subprocess.run(
                        ['taskkill', '/F', '/IM', 'gradle.exe'],
                        capture_output=True, timeout=5
                    )
                    time.sleep(0.2)
                except Exception:
                    pass
            else:
                # On Linux/macOS
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        except Exception:
            pass
        finally:
            # Always close pipes
            self._close_pipes()


    def is_alive(self):
        """Check if the capture process is still running."""
        return self.process is not None and self.process.poll() is None
