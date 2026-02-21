"""FlowMeter Source
Scapy-based live network flow capture using the cicflowmeter pip package.
Captures packets, extracts flow features, maps columns to CICIDS2018 format,
and pushes flows to the classification pipeline queue.

Requirements:
  - pip install cicflowmeter  (pulls in scapy, numpy, scipy)
  - Npcap (Windows) or libpcap (Linux) for packet capture
  - Admin/root privileges for raw packet capture
"""

import os
import sys
import threading
import queue
import time
import logging

# Suppress Scapy import noise before any scapy imports
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

# Windows-specific flags
_IS_WINDOWS = sys.platform.startswith('win')

# Add project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_IDENTIFIER_COLUMNS, CLASSIFICATION_WIFI_KEYWORDS,
    CLASSIFICATION_ETHERNET_KEYWORDS, CLASSIFICATION_EXCLUDE_KEYWORDS,
    FLOWMETER_IDLE_THRESHOLD, FLOWMETER_AGE_THRESHOLD, FLOWMETER_GC_INTERVAL,
    COLOR_CYAN, COLOR_RED, COLOR_GREEN, COLOR_YELLOW,
    COLOR_BLUE, COLOR_DARK_GRAY, COLOR_RESET
)

# Keep backward compatibility
IDENTIFIER_COLUMNS = CLASSIFICATION_IDENTIFIER_COLUMNS


# ============================================================
# Python CICFlowMeter column name → Training data column name
# The pip package 'cicflowmeter' uses snake_case keys in its
# flow.get_data() output. Map them to the CICIDS2018 training
# data column names that the trained model expects.
# ============================================================
PYTHON_CFM_TO_TRAINING = {
    # Identifiers (preserved for display, dropped by preprocessor)
    "src_ip": "Src IP",
    "dst_ip": "Dst IP",
    "src_port": "Src Port",
    "dst_port": "Dst Port",
    "protocol": "Protocol",
    "timestamp": "Timestamp",

    # Flow duration and rates
    "flow_duration": "Flow Duration",
    "flow_byts_s": "Flow Byts/s",
    "flow_pkts_s": "Flow Pkts/s",
    "fwd_pkts_s": "Fwd Pkts/s",
    "bwd_pkts_s": "Bwd Pkts/s",

    # Packet counts
    "tot_fwd_pkts": "Tot Fwd Pkts",
    "tot_bwd_pkts": "Tot Bwd Pkts",

    # Packet lengths
    "totlen_fwd_pkts": "TotLen Fwd Pkts",
    "totlen_bwd_pkts": "TotLen Bwd Pkts",
    "fwd_pkt_len_max": "Fwd Pkt Len Max",
    "fwd_pkt_len_min": "Fwd Pkt Len Min",
    "fwd_pkt_len_mean": "Fwd Pkt Len Mean",
    "fwd_pkt_len_std": "Fwd Pkt Len Std",
    "bwd_pkt_len_max": "Bwd Pkt Len Max",
    "bwd_pkt_len_min": "Bwd Pkt Len Min",
    "bwd_pkt_len_mean": "Bwd Pkt Len Mean",
    "bwd_pkt_len_std": "Bwd Pkt Len Std",
    "pkt_len_max": "Pkt Len Max",
    "pkt_len_min": "Pkt Len Min",
    "pkt_len_mean": "Pkt Len Mean",
    "pkt_len_std": "Pkt Len Std",
    "pkt_len_var": "Pkt Len Var",

    # Header lengths
    "fwd_header_len": "Fwd Header Len",
    "bwd_header_len": "Bwd Header Len",
    "fwd_seg_size_min": "Fwd Seg Size Min",
    "fwd_act_data_pkts": "Fwd Act Data Pkts",

    # Flow IAT (Inter-Arrival Time)
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "flow_iat_std": "Flow IAT Std",

    # Forward IAT
    "fwd_iat_tot": "Fwd IAT Tot",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",

    # Backward IAT
    "bwd_iat_tot": "Bwd IAT Tot",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",

    # Flag counts (directional)
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",

    # Flag counts (total)
    "fin_flag_cnt": "FIN Flag Cnt",
    "syn_flag_cnt": "SYN Flag Cnt",
    "rst_flag_cnt": "RST Flag Cnt",
    "psh_flag_cnt": "PSH Flag Cnt",
    "ack_flag_cnt": "ACK Flag Cnt",
    "urg_flag_cnt": "URG Flag Cnt",
    "ece_flag_cnt": "ECE Flag Cnt",
    "cwr_flag_count": "CWE Flag Count",

    # Ratios and averages
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Pkt Size Avg",
    "fwd_seg_size_avg": "Fwd Seg Size Avg",
    "bwd_seg_size_avg": "Bwd Seg Size Avg",

    # Bulk statistics
    "fwd_byts_b_avg": "Fwd Byts/b Avg",
    "fwd_pkts_b_avg": "Fwd Pkts/b Avg",
    "fwd_blk_rate_avg": "Fwd Blk Rate Avg",
    "bwd_byts_b_avg": "Bwd Byts/b Avg",
    "bwd_pkts_b_avg": "Bwd Pkts/b Avg",
    "bwd_blk_rate_avg": "Bwd Blk Rate Avg",

    # Subflow statistics
    "subflow_fwd_pkts": "Subflow Fwd Pkts",
    "subflow_fwd_byts": "Subflow Fwd Byts",
    "subflow_bwd_pkts": "Subflow Bwd Pkts",
    "subflow_bwd_byts": "Subflow Bwd Byts",

    # Window sizes
    "init_fwd_win_byts": "Init Fwd Win Byts",
    "init_bwd_win_byts": "Init Bwd Win Byts",

    # Active/Idle statistics
    "active_max": "Active Max",
    "active_min": "Active Min",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
}

# ============================================================
# Time-based fields: seconds → microseconds conversion
#
# The Python CICFlowMeter uses Scapy timestamps (seconds as float),
# but the Java CICFlowMeter (and the CICIDS2018 training data)
# stores all time values in MICROSECONDS.
# These fields must be multiplied by 1,000,000.
#
# Note: Rate fields (bytes/s, pkts/s) do NOT need conversion
# because both implementations divide by duration-in-seconds.
# ============================================================
TIME_BASED_FIELDS = {
    "flow_duration",
    "flow_iat_mean", "flow_iat_max", "flow_iat_min", "flow_iat_std",
    "fwd_iat_tot", "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
    "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean", "bwd_iat_std",
    "active_max", "active_min", "active_mean", "active_std",
    "idle_max", "idle_min", "idle_mean", "idle_std",
}

SECONDS_TO_MICROSECONDS = 1_000_000


# ============================================================
# QueueWriter — bridges FlowSession output to the NIDS pipeline
# ============================================================

class QueueWriter:
    """Receives flow dicts from FlowSession, maps column names to
    CICIDS2018 training format, converts time units, and pushes
    them to the preprocessing queue."""

    def __init__(self, flow_queue, identifier_columns):
        self.flow_queue = flow_queue
        self.identifier_columns = identifier_columns
        self.flow_count = 0

    def write(self, data: dict) -> None:
        """Called by FlowSession.garbage_collect() when a flow is completed/expired."""
        try:
            # Generate Flow ID (not produced by Python CICFlowMeter, but needed for identifiers)
            flow_id = (
                f"{data.get('src_ip', '?')}-{data.get('dst_ip', '?')}-"
                f"{data.get('src_port', '?')}-{data.get('dst_port', '?')}-"
                f"{data.get('protocol', '?')}"
            )

            # Map column names and convert time units
            mapped = {"Flow ID": flow_id}
            for python_key, value in data.items():
                training_key = PYTHON_CFM_TO_TRAINING.get(python_key)
                if training_key is None:
                    continue  # Skip unmapped fields (internal keys, etc.)

                # Convert time-based fields from seconds to microseconds
                if python_key in TIME_BASED_FIELDS:
                    try:
                        value = float(value) * SECONDS_TO_MICROSECONDS
                    except (ValueError, TypeError):
                        pass

                mapped[training_key] = value

            # Extract identifiers for threat display / reporting
            identifiers = {}
            for id_col in self.identifier_columns:
                if id_col in mapped:
                    identifiers[id_col] = mapped[id_col]

            mapped["__identifiers__"] = identifiers

            # Push to preprocessing queue
            self.flow_queue.put(mapped)
            self.flow_count += 1

            # Print first few flows to verify capture
            if self.flow_count == 1:
                print(f"{COLOR_CYAN}[FLOWMETER] First flow received! "
                      f"Src={identifiers.get('Src IP', '?')} → "
                      f"Dst={identifiers.get('Dst IP', '?')}:{identifiers.get('Dst Port', '?')}{COLOR_RESET}")
            elif self.flow_count <= 5:
                print(f"{COLOR_CYAN}[FLOWMETER] Flow #{self.flow_count}: "
                      f"Src={identifiers.get('Src IP', '?')} → "
                      f"Dst={identifiers.get('Dst IP', '?')}:{identifiers.get('Dst Port', '?')}{COLOR_RESET}")

        except Exception as e:
            print(f"{COLOR_YELLOW}[FLOWMETER] Flow write error: {e}{COLOR_RESET}")

    def __del__(self):
        pass


# ============================================================
# NIDS-configured FlowSession with faster timeouts
# ============================================================

def _create_nids_session(flow_queue, identifier_columns, verbose=False):
    """Create a FlowSession configured for real-time NIDS with faster
    garbage collection thresholds (idle 15 sec, age 30 sec)."""
    from cicflowmeter.flow_session import FlowSession

    # Create session with a dummy CSV output (we immediately replace the writer)
    session = FlowSession(
        output_mode="csv",
        output=os.devnull,
        fields=None,
        verbose=verbose,
    )

    # Close the dummy CSV writer's file handle before replacing
    try:
        if hasattr(session.output_writer, 'file'):
            session.output_writer.file.close()
    except Exception:
        pass

    # Replace with our queue-based writer
    session.output_writer = QueueWriter(flow_queue, identifier_columns)

    # Override garbage_collect with faster thresholds for real-time NIDS
    idle_threshold = FLOWMETER_IDLE_THRESHOLD
    age_threshold = FLOWMETER_AGE_THRESHOLD

    def fast_garbage_collect(latest_time):
        """Custom GC with faster flow emission thresholds.

        Emits a flow when:
          - latest_time is None (flush all flows at shutdown)
          - Flow has been idle for > idle_threshold seconds
          - Flow total duration > age_threshold seconds
        """
        with session._lock:
            keys = list(session.flows.keys())

        for k in keys:
            with session._lock:
                flow = session.flows.get(k)

            if not flow:
                continue

            # When latest_time is None, flush ALL flows (shutdown)
            if latest_time is not None:
                idle_time = latest_time - flow.latest_timestamp
                flow_age = flow.duration

                # Keep flow if not idle enough AND not old enough
                if idle_time < idle_threshold and flow_age < age_threshold:
                    continue

            # Emit the flow
            data = flow.get_data(session.fields)

            with session._lock:
                if k in session.flows:
                    del session.flows[k]

            session.output_writer.write(data)

    session.garbage_collect = fast_garbage_collect

    return session


def _start_periodic_gc(session, interval):
    """Start a background thread for periodic garbage collection of expired flows."""
    stop_event = threading.Event()

    def _gc_loop():
        while not stop_event.wait(interval):
            try:
                session.garbage_collect(time.time())
            except Exception:
                pass

    t = threading.Thread(target=_gc_loop, name="flow-gc", daemon=True)
    t.start()
    session._gc_thread = t
    session._gc_stop = stop_event


# ============================================================
# Interface listing using Scapy
# ============================================================

def list_interfaces():
    """
    List available network interfaces using Scapy.
    Returns list of dicts with keys: index, name, description, addresses.
    Same format as the old Java-based list_interfaces() for compatibility.
    """
    try:
        # On Windows, explicitly load the arch module to trigger Npcap detection.
        # Without this, conf.ifaces stays None on some Scapy/Python versions.
        if _IS_WINDOWS:
            import scapy.arch.windows  # noqa: F401
        from scapy.config import conf
        from scapy.interfaces import get_working_ifaces
    except ImportError:
        print(f"{COLOR_RED}[ERROR] Scapy is not installed.{COLOR_RESET}")
        print(f"{COLOR_YELLOW}  Run: pip install cicflowmeter{COLOR_RESET}")
        return []

    interfaces = []

    try:
        # Suppress Scapy's internal route/interface warnings
        conf.verb = 0

        # get_working_ifaces returns interfaces that can actually sniff
        working = get_working_ifaces()

        for idx, iface in enumerate(working):
            name = iface.name if hasattr(iface, 'name') else str(iface)
            description = getattr(iface, 'description', None) or "N/A"
            ip = getattr(iface, 'ip', None) or "N/A"
            mac = getattr(iface, 'mac', None) or ""

            # Format addresses
            addr_parts = []
            if ip and ip != "N/A" and ip != "0.0.0.0":
                addr_parts.append(ip)
            if mac and mac != "N/A" and mac != "00:00:00:00:00:00":
                addr_parts.append(f"[{mac}]")
            addresses = " ".join(addr_parts) if addr_parts else "N/A"

            interfaces.append({
                "index": idx,
                "name": name,
                "description": description,
                "addresses": addresses,
            })

    except Exception as e:
        print(f"{COLOR_YELLOW}[FLOWMETER] get_working_ifaces() failed: {e}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}[FLOWMETER] Falling back to basic interface listing...{COLOR_RESET}")

        # Fallback: basic interface listing
        try:
            from scapy.interfaces import get_if_list
            for idx, name in enumerate(get_if_list()):
                # Skip loopback
                if name.lower() in ("lo", "loopback"):
                    continue
                interfaces.append({
                    "index": idx,
                    "name": name,
                    "description": "N/A",
                    "addresses": "N/A",
                })
        except Exception as e2:
            print(f"{COLOR_RED}[ERROR] Interface enumeration failed: {e2}{COLOR_RESET}")

    if not interfaces:
        print(f"{COLOR_RED}[ERROR] No network interfaces detected.{COLOR_RESET}")
        if _IS_WINDOWS:
            print(f"{COLOR_YELLOW}  Ensure Npcap is installed: https://npcap.com{COLOR_RESET}")
            print(f"{COLOR_YELLOW}  Check 'Install Npcap in WinPcap API-compatible Mode'{COLOR_RESET}")
            print(f"{COLOR_YELLOW}  Run as Administrator if Npcap is installed.{COLOR_RESET}")
        else:
            print(f"{COLOR_YELLOW}  Ensure libpcap is installed:{COLOR_RESET}")
            print(f"{COLOR_YELLOW}    Ubuntu/Debian:  sudo apt install libpcap-dev{COLOR_RESET}")
            print(f"{COLOR_YELLOW}    Fedora/RHEL:    sudo dnf install libpcap-devel{COLOR_RESET}")
            print(f"{COLOR_YELLOW}    Arch Linux:     sudo pacman -S libpcap{COLOR_RESET}")
            print(f"{COLOR_YELLOW}  Run with sudo or set capabilities:{COLOR_RESET}")
            print(f"{COLOR_YELLOW}    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3)){COLOR_RESET}")

    return interfaces


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
        is_wifi = any(kw in desc_lower or kw in name_lower for kw in wifi_keywords)
        is_excluded = any(kw in desc_lower or kw in name_lower for kw in exclude_keywords)
        if is_wifi and not is_excluded:
            wifi_list.append(iface)

    return wifi_list


def get_ethernet_interfaces(interfaces):
    """
    Get all Ethernet adapters from the list of interfaces.
    Returns list of interface dicts matching Ethernet keywords.
    """
    wifi_keywords = CLASSIFICATION_WIFI_KEYWORDS
    ethernet_keywords = CLASSIFICATION_ETHERNET_KEYWORDS
    exclude_keywords = CLASSIFICATION_EXCLUDE_KEYWORDS
    ethernet_list = []

    for iface in interfaces:
        desc_lower = iface["description"].lower()
        name_lower = iface["name"].lower()
        is_ethernet = any(kw in desc_lower or kw in name_lower for kw in ethernet_keywords)
        is_wifi = any(kw in desc_lower or kw in name_lower for kw in wifi_keywords)
        is_excluded = any(kw in desc_lower or kw in name_lower for kw in exclude_keywords)
        if is_ethernet and not is_wifi and not is_excluded:
            ethernet_list.append(iface)

    # Fallback: if no explicit ethernet match, include non-wifi non-excluded interfaces
    if not ethernet_list:
        for iface in interfaces:
            desc_lower = iface["description"].lower()
            name_lower = iface["name"].lower()
            is_wifi = any(kw in desc_lower or kw in name_lower for kw in wifi_keywords)
            is_excluded = any(kw in desc_lower or kw in name_lower for kw in exclude_keywords)
            if name_lower in ("lo", "loopback"):
                continue
            if not is_wifi and not is_excluded:
                ethernet_list.append(iface)

    return ethernet_list


# ============================================================
# FlowMeterSource — Main flow capture class
# ============================================================

class FlowMeterSource:
    """Manages Scapy-based live packet capture and flow feature extraction
    using the cicflowmeter Python package."""

    def __init__(self, flow_queue, interface_name=None, stop_event=None):
        """
        Args:
            flow_queue: queue.Queue to push parsed flow dicts into
            interface_name: network interface device name (auto-detect WiFi if None)
            stop_event: threading.Event (not used internally; source has its own)
        """
        self.flow_queue = flow_queue
        self.interface_name = interface_name
        self._stop_event = threading.Event()
        self._packet_count = 0
        self._packet_count_lock = threading.Lock()

        # Internal components
        self._sniffer = None
        self._session = None
        self._gc_thread = None
        self._gc_stop = None

    @property
    def flow_count(self):
        """Total flows emitted to the queue."""
        try:
            return self._session.output_writer.flow_count
        except (AttributeError, TypeError):
            return 0

    def start(self):
        """Start the Scapy-based flow capture."""
        if self.interface_name is None:
            print(f"{COLOR_RED}[FLOWMETER] No interface specified!{COLOR_RESET}")
            return False

        # Check if cicflowmeter package is available
        try:
            # On Windows, explicitly trigger Npcap detection
            if _IS_WINDOWS:
                import scapy.arch.windows  # noqa: F401
            from cicflowmeter.flow_session import FlowSession
            from scapy.sendrecv import AsyncSniffer
            from scapy.config import conf
        except ImportError as e:
            print(f"{COLOR_RED}[FLOWMETER] Missing dependency: {e}{COLOR_RESET}")
            print(f"{COLOR_YELLOW}  Install with: pip install cicflowmeter{COLOR_RESET}")
            return False

        # Suppress Scapy console output
        conf.verb = 0

        print(f"{COLOR_CYAN}[FLOWMETER] Starting capture on: {self.interface_name}{COLOR_RESET}")

        try:
            # Create the NIDS-configured flow session with queue output
            self._session = _create_nids_session(
                flow_queue=self.flow_queue,
                identifier_columns=IDENTIFIER_COLUMNS,
                verbose=False,
            )

            # Wrap session.process to count packets for status display
            original_process = self._session.process

            def counting_process(pkt):
                with self._packet_count_lock:
                    self._packet_count += 1
                return original_process(pkt)

            # Start periodic garbage collection
            _start_periodic_gc(self._session, interval=FLOWMETER_GC_INTERVAL)
            self._gc_thread = self._session._gc_thread
            self._gc_stop = self._session._gc_stop

            # Create and start AsyncSniffer
            self._sniffer = AsyncSniffer(
                iface=self.interface_name,
                filter="ip and (tcp or udp)",
                prn=counting_process,
                store=False,
            )
            self._sniffer.start()

            print(f"{COLOR_GREEN}[FLOWMETER] Capture started. Listening for packets...{COLOR_RESET}")
            print(f"{COLOR_CYAN}[FLOWMETER] Flow emission: idle>{FLOWMETER_IDLE_THRESHOLD}s "
                  f"or age>{FLOWMETER_AGE_THRESHOLD}s | GC every {FLOWMETER_GC_INTERVAL}s{COLOR_RESET}")
            return True

        except PermissionError:
            print(f"{COLOR_RED}[FLOWMETER] Permission denied for packet capture.{COLOR_RESET}")
            self._print_permission_fix()
            return False
        except OSError as e:
            err_lower = str(e).lower()
            if "permission" in err_lower or "operation not permitted" in err_lower:
                print(f"{COLOR_RED}[FLOWMETER] Permission denied: {e}{COLOR_RESET}")
                self._print_permission_fix()
            elif "no such device" in err_lower:
                print(f"{COLOR_RED}[FLOWMETER] Interface not found: {self.interface_name}{COLOR_RESET}")
                print(f"{COLOR_YELLOW}  Run with --list-interfaces to see available interfaces.{COLOR_RESET}")
            else:
                print(f"{COLOR_RED}[FLOWMETER] OS error: {e}{COLOR_RESET}")
                if _IS_WINDOWS:
                    print(f"{COLOR_YELLOW}  Ensure Npcap is installed: https://npcap.com{COLOR_RESET}")
                else:
                    print(f"{COLOR_YELLOW}  Ensure libpcap is installed on your system.{COLOR_RESET}")
            return False
        except Exception as e:
            print(f"{COLOR_RED}[FLOWMETER] Failed to start: {e}{COLOR_RESET}")
            return False

    def _print_permission_fix(self):
        """Print permission fix instructions."""
        print()
        if _IS_WINDOWS:
            print(f"{COLOR_YELLOW}  Fix: Run this terminal as Administrator.{COLOR_RESET}")
            print(f"{COLOR_YELLOW}  Also ensure Npcap is installed: https://npcap.com{COLOR_RESET}")
        else:
            venv_python = os.path.abspath(os.path.join(PROJECT_ROOT, 'venv', 'bin', 'python'))
            print(f"{COLOR_YELLOW}  Option 1 — Set capabilities once (no sudo needed after):{COLOR_RESET}")
            print(f"{COLOR_YELLOW}    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3)){COLOR_RESET}")
            print()
            print(f"{COLOR_YELLOW}  Option 2 — Run with sudo this time:{COLOR_RESET}")
            print(f"{COLOR_YELLOW}    sudo {venv_python} classification.py{COLOR_RESET}")
        print()

    def stop(self):
        """Stop the capture, flush remaining flows, clean up."""
        self._stop_event.set()

        # Stop the sniffer
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass

        # Stop the GC thread
        if self._gc_stop:
            self._gc_stop.set()
            if self._gc_thread and self._gc_thread.is_alive():
                self._gc_thread.join(timeout=5)

        # Flush all remaining flows
        if self._session:
            try:
                self._session.garbage_collect(None)
            except Exception:
                pass

        print(f"{COLOR_GREEN}[FLOWMETER] Capture stopped. "
              f"Packets: {self._packet_count} | Flows: {self.flow_count}{COLOR_RESET}")

    def is_alive(self):
        """Check if the capture is still running."""
        if self._sniffer is None:
            return False
        if self._stop_event.is_set():
            return False
        try:
            return hasattr(self._sniffer, 'thread') and self._sniffer.thread.is_alive()
        except (AttributeError, RuntimeError):
            return False
