#!/usr/bin/env python
"""
NIDS Classification - Live Traffic Analysis
============================================

Main orchestrator for real-time network traffic classification.

Starts a multi-threaded pipeline:
    FlowMeter Source → Preprocessor → Classifier → Threat Handler + Report Generator

Each component runs in its own thread with queues connecting them.

Usage:
    python classification.py                     # Live capture, auto-detect, 120s, 5-class model
    python classification.py --duration 300      # Live capture for 5 minutes
    python classification.py --model all         # Use 'all' model (6-class with Infilteration)
    python classification.py --interface         # Interactive interface selection menu
    python classification.py --interface "WiFi"  # Use specific interface by name
    python classification.py --batch             # Batch CSV classification (interactive file selection)
    python classification.py --batch file.csv    # Batch CSV classification (specific file)
    python classification.py --help              # Show all options
    
On Linux/macOS, live capture requires elevated privileges:
    sudo ./venv/bin/python classification.py
"""

import os
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning"
import sys
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import argparse
import threading
import queue
import time
import signal

# ============================================================
# VENV CHECK - Verify virtual environment is active
# ============================================================
def check_venv():
    """Check that venv is active and required packages are importable; exit if not."""
    project_root = os.path.dirname(os.path.abspath(__file__))
    venv_dir = os.path.join(project_root, "venv")
    is_win = sys.platform.startswith('win')

    # 1. Check if venv directory exists at all
    if not os.path.isdir(venv_dir):
        print("\n" + "="*80)
        print("ERROR: Virtual environment not found.")
        print("="*80)
        print("\n  Run the setup script first (it will create everything):\n")
        if is_win:
            print("      setup\\setup.bat")
        else:
            print("      source setup/setup.sh")
        print("\n  This will create the venv and install all dependencies.")
        print("="*80 + "\n")
        sys.exit(1)

    # 2. Check if venv is activated
    in_venv = (
        hasattr(sys, 'real_prefix') or  # virtualenv
        (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)  # venv
    )
    if not in_venv:
        print("\n" + "="*80)
        print("ERROR: Virtual environment is not activated.")
        print("="*80)
        print("\n  Activate it first, then run again:\n")
        if is_win:
            print("      venv\\Scripts\\activate")
            print("      python classification.py\n")
        else:
            print("      source venv/bin/activate")
            print("      python classification.py\n")
        print("="*80 + "\n")
        sys.exit(1)

    # 3. Check if required packages are installed
    required = ["sklearn", "pandas", "numpy", "joblib"]
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print("\n" + "="*80)
        print("ERROR: Missing required packages: " + ", ".join(missing))
        print("="*80)
        print("\n  venv is active but dependencies are not installed.")
        print("  Run:\n")
        print("      pip install -r requirements.txt")
        print("      python classification.py\n")
        print("="*80 + "\n")
        sys.exit(1)


# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

# Check venv early
check_venv()

from config import (
    CLASSIFICATION_DEFAULT_DURATION, CLASSIFICATION_DEFAULT_MODEL,
    CLASSIFICATION_QUEUE_MAXSIZE, CLASSIFICATION_STATUS_UPDATE_INTERVAL,
    COLOR_CYAN, COLOR_CYAN_BOLD, COLOR_RED, COLOR_YELLOW, COLOR_GREEN, COLOR_RESET,
    COLOR_DARK_GRAY, COLOR_RED_BOLD
)
from classification.flowmeter_source import (
    FlowMeterSource, list_interfaces, 
    get_wifi_interfaces, get_ethernet_interfaces, get_vm_interfaces
)
from classification.batch_source import BatchSource
from classification.preprocessor import Preprocessor
from classification.classifier import Classifier
from classification.threat_handler import ThreatHandler
from classification.report_generator import ReportGenerator

# Aliases for backward compatibility
DEFAULT_DURATION = CLASSIFICATION_DEFAULT_DURATION
DEFAULT_MODEL = CLASSIFICATION_DEFAULT_MODEL


def select_batch_type_and_file():
    """
    Scan all four batch folders (default/batch, default/batch_labeled,
    all/batch, all/batch_labeled), display files grouped by model variant,
    let the user pick one, and auto-select the correct model.

    Returns:
        tuple: (file_path, has_label, use_all_classes) or (None, None, None)
    """
    from classification_batch.batch_utils import select_batch_file
    return select_batch_file()

class ClassificationSession:
    """
    A single classification session that manages the full pipeline.
    Multiple sessions can run independently in separate thread groups.
    """

    def __init__(self, mode="live", interface_name=None, duration=DEFAULT_DURATION,
                 use_all_classes=False, session_id=1, batch_file_path=None, has_batch_label=False,
                 vm_mode=False, debug=False):
        """
        Args:
            mode: 'live' or 'batch'
            interface_name: network interface device name (None = auto-detect WiFi) [for live mode]
            duration: capture duration in seconds [for live mode]
            use_all_classes: use 'all' model if True
            session_id: unique session identifier
            batch_file_path: path to batch CSV file (for batch mode)
            has_batch_label: if True, batch file has actual labels
            vm_mode: if True, auto-select VirtualBox/VM adapter instead of WiFi
            debug: if True, print detailed feature values for first N flows
        """
        self.mode = mode
        self.interface_name = interface_name
        self.duration = duration
        self.use_all_classes = use_all_classes
        self.session_id = session_id
        self.batch_file_path = batch_file_path
        self.has_batch_label = has_batch_label
        self.vm_mode = vm_mode
        self.debug = debug

        # Shared stop event for all threads in this session
        self.stop_event = threading.Event()
        
        # Batch completion event (set by report_generator after writing batch reports)
        self.batch_completion_event = threading.Event()

        # Inter-thread queues
        self.flow_queue = queue.Queue(maxsize=CLASSIFICATION_QUEUE_MAXSIZE)
        self.classifier_queue = queue.Queue(maxsize=CLASSIFICATION_QUEUE_MAXSIZE)
        self.threat_queue = queue.Queue(maxsize=CLASSIFICATION_QUEUE_MAXSIZE)
        self.report_queue = queue.Queue(maxsize=CLASSIFICATION_QUEUE_MAXSIZE)

        # Components
        self.source = None
        self.preprocessor = None
        self.classifier = None
        self.threat_handler = None
        self.report_generator = None

        # Threads
        self.threads = []

    def _print_banner(self):
        """Print session start banner."""
        model_name = "All (with Infilteration)" if self.use_all_classes else "Default"
        print(f"\n{COLOR_CYAN}{'='*80}{COLOR_RESET}")
        print(f"{COLOR_CYAN_BOLD}  SESSION STARTED{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'='*80}{COLOR_RESET}")
        print(f"{COLOR_CYAN}  ID:       {self.session_id}{COLOR_RESET}")
        print(f"{COLOR_CYAN}  Mode:     {self.mode.upper()}{COLOR_RESET}")
        print(f"{COLOR_CYAN}  Model:    {model_name}{COLOR_RESET}")
        if self.mode == "batch":
            print(f"{COLOR_CYAN}  File:     {os.path.basename(self.batch_file_path)}{COLOR_RESET}")
        else:
            print(f"{COLOR_CYAN}  Duration: {self.duration} seconds{COLOR_RESET}")
            if self.interface_name:
                print(f"{COLOR_CYAN}  Interface: {self.interface_name}{COLOR_RESET}")
            else:
                print(f"{COLOR_CYAN}  Interface: Auto-detect WiFi{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'='*80}{COLOR_RESET}\n")

    def start(self):
        """Start the classification pipeline."""
        self._print_banner()

        if self.mode == "live":
            # Auto-select interface if not specified
            if self.interface_name is None:
                interfaces = list_interfaces()
                
                if self.vm_mode:
                    # VM mode: prefer VirtualBox/VM adapters
                    vm_ifaces = get_vm_interfaces(interfaces)
                    if vm_ifaces:
                        self.interface_name = vm_ifaces[0]['name']
                        desc = vm_ifaces[0].get('description', self.interface_name)
                        print(f"{COLOR_CYAN}[SESSION] VM mode: Selected VirtualBox adapter: {desc}{COLOR_RESET}")
                    else:
                        print(f"{COLOR_RED}[SESSION] --vm specified but no VirtualBox/VM adapters found!{COLOR_RESET}")
                        print(f"{COLOR_YELLOW}  Available interfaces:{COLOR_RESET}")
                        for iface in interfaces:
                            print(f"    {iface['description']} ({iface['name']})")
                        print(f"{COLOR_YELLOW}\n  Use --interface to specify manually, or --list-interfaces to see all.{COLOR_RESET}")
                        return False
                else:
                    # Normal mode: prefer WiFi, then Ethernet
                    wifi_ifaces = get_wifi_interfaces(interfaces)
                    eth_ifaces = get_ethernet_interfaces(interfaces)
                    
                    if wifi_ifaces:
                        self.interface_name = wifi_ifaces[0]['name']
                        print(f"{COLOR_CYAN}[SESSION] Auto-selected WiFi interface: {self.interface_name}{COLOR_RESET}")
                    elif eth_ifaces:
                        self.interface_name = eth_ifaces[0]['name']
                        print(f"{COLOR_CYAN}[SESSION] Auto-selected Ethernet interface: {self.interface_name}{COLOR_RESET}")
                    else:
                        # No interfaces detected — check if we're on Linux without sudo
                        if not sys.platform.startswith('win'):
                            try:
                                if os.geteuid() != 0:
                                    print(f"{COLOR_RED}[SESSION] No network interfaces detected.{COLOR_RESET}")
                                    print(f"{COLOR_YELLOW}\nThis is expected on Linux without elevated privileges.{COLOR_RESET}")
                                    print(f"{COLOR_YELLOW}\nRun with sudo:{COLOR_RESET}")
                                    print(f"{COLOR_CYAN}      sudo ./venv/bin/python classification.py{COLOR_RESET}")
                                    print(f"{COLOR_YELLOW}\nOr grant Python capabilities (one-time):{COLOR_RESET}")
                                    import subprocess
                                    python_path = subprocess.check_output(["readlink", "-f", sys.executable]).decode().strip()
                                    print(f"{COLOR_CYAN}      sudo setcap cap_net_raw,cap_net_admin=eip {python_path}{COLOR_RESET}\n")
                                    return False
                            except Exception:
                                pass
                    
                    print(f"{COLOR_RED}[SESSION] No network interfaces available!{COLOR_RESET}")
                    return False
            
            return self._start_live()
        elif self.mode == "batch":
            return self._start_batch()
        else:
            print(f"{COLOR_RED}[SESSION] Unknown mode: {self.mode}{COLOR_RESET}")
            return False

    def _start_live(self):
        """Start the live capture pipeline."""

        # Check for elevated privileges upfront on Linux/macOS (required for Scapy packet capture)
        if not sys.platform.startswith('win'):
            try:
                if os.geteuid() != 0:
                    print(f"{COLOR_RED}[ERROR] Cannot capture packets without elevated privileges on Linux/macOS.{COLOR_RESET}")
                    print(f"{COLOR_YELLOW}\n  Option 1: Run with sudo + full Python path:{COLOR_RESET}")
                    print(f"{COLOR_CYAN}      sudo ./venv/bin/python classification.py{COLOR_RESET}")
                    print(f"{COLOR_YELLOW}\n  Option 2: Grant Python capabilities (one-time setup, no sudo needed later):{COLOR_RESET}")
                    import subprocess
                    python_path = subprocess.check_output(["readlink", "-f", sys.executable]).decode().strip()
                    print(f"{COLOR_CYAN}      sudo setcap cap_net_raw,cap_net_admin=eip {python_path}{COLOR_RESET}\n")
                    return False
            except Exception:
                pass  # If we can't check, proceed anyway

        # 1. Create flow capture source (Python CICFlowMeter / Scapy)
        try:
            self.source = FlowMeterSource(
                flow_queue=self.flow_queue,
                interface_name=self.interface_name,
                stop_event=self.stop_event,
            )
        except PermissionError as e:
            print(f"{COLOR_RED}[ERROR] Permission denied. Cannot capture packets on {self.interface_name}.{COLOR_RESET}")
            print(f"{COLOR_YELLOW}\nThis requires elevated privileges on Linux/macOS.{COLOR_RESET}")
            print(f"{COLOR_YELLOW}\n  Run with sudo + full Python path:{COLOR_RESET}")
            print(f"{COLOR_CYAN}      sudo ./venv/bin/python classification.py{COLOR_RESET}\n")
            return False
        except Exception as e:
            print(f"{COLOR_RED}[ERROR] Failed to start packet capture: {e}{COLOR_RESET}")
            return False

        # 2. Create preprocessor
        self.preprocessor = Preprocessor(
            flow_queue=self.flow_queue,
            classifier_queue=self.classifier_queue,
            stop_event=self.stop_event,
            use_all_classes=self.use_all_classes,
            mode=self.mode,
            debug=self.debug,
        )

        # 3. Create classifier
        self.classifier = Classifier(
            classifier_queue=self.classifier_queue,
            threat_queue=self.threat_queue,
            report_queue=self.report_queue,
            stop_event=self.stop_event,
            use_all_classes=self.use_all_classes,
            mode=self.mode,
            debug=self.debug,
        )

        # 4. Create threat handler
        self.threat_handler = ThreatHandler(
            threat_queue=self.threat_queue,
            stop_event=self.stop_event,
        )

        # 5. Create report generator
        model_label = "all" if self.use_all_classes else "default"
        iface_display = self.interface_name or "auto-detect"
        self.report_generator = ReportGenerator(
            report_queue=self.report_queue,
            stop_event=self.stop_event,
            mode=self.mode,
            model_name=model_label,
            duration=self.duration,
            interface_name=iface_display,
            batch_completion_event=self.batch_completion_event,
        )

        # Start flow capture source (Scapy-based, not a subprocess)
        if not self.source.start():
            print(f"{COLOR_RED}[SESSION] Failed to start flow capture source.{COLOR_RESET}")
            return False

        # Start pipeline threads
        thread_targets = [
            ("preprocessor", self.preprocessor.run),
            ("classifier", self.classifier.run),
            ("threat-handler", self.threat_handler.run),
            ("report-gen", self.report_generator.run),
        ]

        for name, target in thread_targets:
            t = threading.Thread(
                target=target,
                name=f"session-{self.session_id}-{name}",
                daemon=True,
            )
            t.start()
            self.threads.append(t)

        print(f"{COLOR_GREEN}[SESSION] Pipeline started with {len(self.threads)} threads + flow capture{COLOR_RESET}")
        print(f"{COLOR_GREEN}[SESSION] Capturing for {self.duration} seconds. Press Ctrl+C to stop early.{COLOR_RESET}\n")

        return True

    def _start_batch(self):
        """
        Start fast vectorized batch processing.
        Uses classification_batch/ pipeline: Source → Preprocessor → Classifier → Report.
        """
        from classification_batch.batch_classify import run_batch_classification

        result = run_batch_classification(
            csv_path=self.batch_file_path,
            use_all_classes=self.use_all_classes,
            has_label=self.has_batch_label,
        )

        # Store report generator for summary printing
        self.report_generator = result["report_generator"]
        self.batch_completion_event.set()
        return True

    def wait(self):
        """Wait for the session to complete.
        
        For live mode: waits for duration or stop signal
        For batch mode: _start_batch() is synchronous, so completion event is already set
        """
        try:
            if self.mode == "batch":
                # Batch mode is synchronous — _start_batch() already completed and set the event.
                # Just confirm it's done.
                if not self.batch_completion_event.is_set():
                    print(f"{COLOR_CYAN}[SESSION] Waiting for batch completion...{COLOR_RESET}")
                    self.batch_completion_event.wait(timeout=600)
            else:
                # Live mode: wait for duration
                start_time = time.time()
                while not self.stop_event.is_set():
                    elapsed = time.time() - start_time
                    remaining = self.duration - elapsed

                    if remaining <= 0:
                        print(f"\n{COLOR_CYAN}[SESSION] Duration reached ({self.duration}s). Stopping...{COLOR_RESET}")
                        break

                    # Print periodic status
                    if int(elapsed) % CLASSIFICATION_STATUS_UPDATE_INTERVAL == 0 and int(elapsed) > 0:
                        flows = self.source.flow_count if self.source else 0
                        classified = self.classifier.classified_count if self.classifier else 0
                        packets = self.source._packet_count if self.source else 0
                        sniffer_alive = "yes" if (self.source and self.source.is_alive()) else "no"
                        print(f"{COLOR_DARK_GRAY}[SESSION] {int(elapsed)}s elapsed | "
                              f"Sniffer: {sniffer_alive} | "
                              f"Packets: {packets} | Flows: {flows} | Classified: {classified} | "
                              f"Remaining: {int(remaining)}s{COLOR_RESET}")

                    time.sleep(1)

        except KeyboardInterrupt:
            print(f"\n{COLOR_YELLOW}[SESSION] Interrupted by user. Stopping...{COLOR_RESET}")

    def stop(self):
        """Stop the session with proper hierarchical shutdown.

        Pipeline:  Source → Preprocessor → Classifier → ThreatHandler + ReportGenerator

        Shutdown order (bottom-up — downstream first would lose data,
        so we stop the *source* first, let data drain through, then
        join threads in pipeline order):

        1. Stop CICFlowMeter source  (no more new flows)
        2. Inject None sentinel into flow_queue
        3. Join Preprocessor          (drains flow_queue, forwards to classifier_queue, exits)
        4. Join Classifier            (drains classifier_queue, forwards to threat/report queues, exits)
        5. Join ThreatHandler         (drains threat_queue, exits)
        6. Join ReportGenerator       (drains report_queue, writes final reports, exits)
        7. Set stop_event             (final fallback)
        8. Print summary
        """
        THREAD_JOIN_TIMEOUT = 90

        print(f"\n{COLOR_CYAN}[SESSION] Shutting down session {self.session_id}...{COLOR_RESET}")

        # ── Step 1: Stop the flow capture source ──────────────────────────
        if self.source:
            self.source.stop()

        # ── Step 2: Inject sentinel so threads know input is finished ──────
        if self.mode != "batch":
            self.flow_queue.put(None)

        # ── Steps 3-6: Join threads in pipeline order ──────────────────────
        # threads[] was built as [preprocessor, classifier, threat-handler, report-gen]
        pipeline_labels = ["Preprocessor", "Classifier", "ThreatHandler", "ReportGenerator"]

        for i, label in enumerate(pipeline_labels):
            if i < len(self.threads):
                t = self.threads[i]
                t.join(timeout=THREAD_JOIN_TIMEOUT)
                if t.is_alive():
                    print(f"{COLOR_YELLOW}[SESSION] {label} did not stop within {THREAD_JOIN_TIMEOUT}s{COLOR_RESET}")
                else:
                    print(f"{COLOR_GREEN}[SESSION] {label} stopped.{COLOR_RESET}")

        # Join any extra threads that may have been appended
        for t in self.threads[len(pipeline_labels):]:
            t.join(timeout=THREAD_JOIN_TIMEOUT)

        # ── Step 7: Final fallback ─────────────────────────────────────────
        self.stop_event.set()

        # ── Step 8: Summary ────────────────────────────────────────────────
        self._print_summary()

    def _print_summary(self):
        """Print final session summary."""
        print(f"\n{COLOR_CYAN}{'='*80}{COLOR_RESET}")
        print(f"{COLOR_CYAN_BOLD}  SESSION COMPLETE: {self.session_id}{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'='*80}{COLOR_RESET}")

        if self.mode == "batch":
            # Batch mode summary comes from classification_batch pipeline
            if self.report_generator:
                stats = self.report_generator.stats
                print(f"  Total flows:       {stats.get('total', 0)}")
                print(f"  {COLOR_RED}Threats:           {stats.get('threats', 0)}{COLOR_RESET}")
                print(f"  {COLOR_YELLOW}Suspicious:        {stats.get('suspicious', 0)}{COLOR_RESET}")
                print(f"  {COLOR_GREEN}Clean:             {stats.get('clean', 0)}{COLOR_RESET}")
                if 'accuracy' in stats and stats.get('accuracy', 0) > 0:
                    print(f"  Accuracy:          {stats['accuracy']:.2f}%")
                print(f"  Report folder:     {self.report_generator.report_path}")
        else:
            # Live mode summary
            if self.source:
                print(f"  Flows captured:    {self.source.flow_count}")
            if self.preprocessor:
                print(f"  Flows preprocessed: {self.preprocessor.processed_count}")
            if self.classifier:
                print(f"  Flows classified:  {self.classifier.classified_count}")
            if self.threat_handler:
                print(f"  {COLOR_RED}Threats (RED):     {self.threat_handler.red_count}{COLOR_RESET}")
                print(f"  {COLOR_YELLOW}Suspicious (YELLOW): {self.threat_handler.yellow_count}{COLOR_RESET}")
                print(f"  {COLOR_GREEN}Clean (GREEN):     {self.threat_handler.green_count}{COLOR_RESET}")
            if self.report_generator:
                print(f"  Report folder:     {self.report_generator.report_path}")

        print(f"{COLOR_CYAN}{'='*80}{COLOR_RESET}\n")


def select_interface_interactive():
    """
    Prompt user to choose an interface by number.
    Shows all interfaces grouped as WiFi / Ethernet / Other.
    Returns the interface name string.
    """
    print(f"\n{COLOR_CYAN_BOLD}Network Interface Selection{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'='*80}{COLOR_RESET}")

    # List all interfaces
    interfaces = list_interfaces()
    if not interfaces:
        print(f"{COLOR_RED}No network interfaces found!{COLOR_RESET}")
        return None

    # Categorize interfaces
    wifi_ifaces = get_wifi_interfaces(interfaces)
    ethernet_ifaces = get_ethernet_interfaces(interfaces)
    vm_ifaces = get_vm_interfaces(interfaces)

    # Build "other" list: everything not in wifi or ethernet
    wifi_names = {i['name'] for i in wifi_ifaces}
    ethernet_names = {i['name'] for i in ethernet_ifaces}
    other_ifaces = [i for i in interfaces
                    if i['name'] not in wifi_names and i['name'] not in ethernet_names]

    # Flat ordered list for selection: WiFi → Ethernet → Other
    all_ifaces = []

    print(f"\n{COLOR_CYAN}Available Interfaces:{COLOR_RESET}\n")

    # Hint if VM adapters are detected
    if vm_ifaces:
        vm_descs = ', '.join(v['description'] for v in vm_ifaces[:3])
        print(f"  {COLOR_YELLOW}TIP: For VM attacks, select the VirtualBox/VMware adapter ({vm_descs}){COLOR_RESET}")
        print(f"  {COLOR_YELLOW}     Or use:  python classification.py --vm  to auto-select it.{COLOR_RESET}\n")

    def _print_group(label, group, start_idx):
        idx = start_idx
        print(f"{COLOR_CYAN_BOLD}{label}:{COLOR_RESET}")
        for iface in group:
            desc = iface['description']
            name = iface['name']
            if desc == "N/A" or not desc:
                print(f"  [{idx}] {name}")
            else:
                print(f"  [{idx}] {desc}")
                print(f"       Name: {name}")
            print(f"       Address: {iface['addresses']}")
            all_ifaces.append(iface)
            idx += 1
        return idx

    idx = 1
    if wifi_ifaces:
        idx = _print_group("WiFi Adapters", wifi_ifaces, idx)
    else:
        print(f"{COLOR_YELLOW}(No WiFi adapters detected){COLOR_RESET}")

    if ethernet_ifaces:
        print()
        idx = _print_group("Ethernet Adapters", ethernet_ifaces, idx)
    else:
        print(f"{COLOR_YELLOW}(No Ethernet adapters detected){COLOR_RESET}")

    if other_ifaces:
        print()
        idx = _print_group(f"{COLOR_DARK_GRAY}Other / Virtual", other_ifaces, idx)

    print(f"\n{COLOR_CYAN}{'='*80}{COLOR_RESET}")

    # Prompt user
    while True:
        try:
            choice = input(f"\n{COLOR_CYAN_BOLD}Enter interface number (1-{len(all_ifaces)}){COLOR_RESET}: ").strip()
            choice_idx = int(choice) - 1

            if 0 <= choice_idx < len(all_ifaces):
                selected = all_ifaces[choice_idx]
                desc = selected['description']
                label = desc if desc and desc != "N/A" else selected['name']
                print(f"\n{COLOR_GREEN}Selected: {label}{COLOR_RESET}\n")
                return selected['name']
            else:
                print(f"{COLOR_RED}Invalid choice. Enter a number between 1 and {len(all_ifaces)}.{COLOR_RESET}")
        except (ValueError, IndexError):
            print(f"{COLOR_RED}Invalid input. Please enter a number.{COLOR_RESET}")
        except EOFError:
            # Headless mode — auto-select WiFi first, then Ethernet
            print(f"\n{COLOR_YELLOW}EOF detected — auto-selecting interface...{COLOR_RESET}")
            if wifi_ifaces:
                selected = wifi_ifaces[0]
            elif ethernet_ifaces:
                selected = ethernet_ifaces[0]
            else:
                print(f"{COLOR_RED}No usable network interfaces!{COLOR_RESET}")
                return None
            desc = selected['description']
            label = desc if desc and desc != "N/A" else selected['name']
            print(f"{COLOR_GREEN}[OK] Auto-selected: {label}{COLOR_RESET}\n")
            return selected['name']


def main():
    parser = argparse.ArgumentParser(
        description="NIDS Real-Time Traffic Classification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python classification.py                          # Live WiFi, 180s, default model
  python classification.py --duration 300           # Live WiFi, 5 minutes
  python classification.py --model all              # Use 'all' model (with Infilteration)
  python classification.py --list-interfaces        # List network interfaces
  python classification.py --interface "\\Device\\NPF_{...}"  # Specific interface
  python classification.py --batch                  # Batch CSV classification (select file)
  python classification.py --batch path/to/file.csv # Batch CSV classification (specific file)
        """
    )

    parser.add_argument(
        "--mode", choices=["live", "batch"], default="live",
        help="Classification mode (default: live)"
    )
    parser.add_argument(
        "--batch", type=str, nargs='?', const='SELECT',
        help="Batch CSV classification: optionally specify CSV file path (default: interactive selection)"
    )
    parser.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION,
        help=f"Capture duration in seconds (default: {DEFAULT_DURATION})"
    )
    parser.add_argument(
        "--model", choices=["default", "all"], default=DEFAULT_MODEL,
        help="Model variant: 'default' or 'all' (with Infilteration)"
    )
    parser.add_argument(
        "--interface", type=str, nargs='?', const='SELECT', default=None,
        help="Network interface: optionally specify adapter name (default: interactive selection)"
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List available network interfaces and exit"
    )
    parser.add_argument(
        "--vm", action="store_true",
        help="VM mode: auto-select VirtualBox/VMware adapter for VM attack detection"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Debug mode: print detailed feature values and prediction probabilities"
    )

    args = parser.parse_args()

    # Handle --list-interfaces
    if args.list_interfaces:
        print(f"\n{COLOR_CYAN}Discovering network interfaces...{COLOR_RESET}\n")
        interfaces = list_interfaces()
        if not interfaces:
            print(f"{COLOR_RED}No network interfaces found.{COLOR_RESET}")
            return

        print(f"{'Idx':<5} {'Description':<55} {'Addresses':<20}")
        print("-" * 80)
        for iface in interfaces:
            print(f"{iface['index']:<5} {iface['description']:<55} {iface['addresses']:<20}")
            print(f"      Name: {iface['name']}")
        return

    # Determine model variant
    use_all = (args.model == "all")

    # Handle batch mode
    mode = args.mode
    batch_file_path = None
    has_batch_label = False
    interface_name = None

    if args.batch is not None:
        # Batch mode requested
        mode = "batch"
        if args.batch == "SELECT":
            # Interactive selection — scans all 4 folders, auto-selects model
            batch_file_path, has_batch_label, batch_use_all = select_batch_type_and_file()
            if batch_file_path is None:
                print(f"{COLOR_RED}[MAIN] No batch file selected. Exiting.{COLOR_RESET}")
                sys.exit(1)
            # Override model based on folder selection
            use_all = batch_use_all
        else:
            # Use provided path — auto-detect model and label from path
            batch_file_path = args.batch
            if not os.path.exists(batch_file_path):
                print(f"{COLOR_RED}[MAIN] Batch file not found: {batch_file_path}{COLOR_RESET}")
                sys.exit(1)
            from classification_batch.batch_utils import detect_model_from_path
            has_batch_label, detected_all = detect_model_from_path(batch_file_path)
            # Only override model if user didn't explicitly pass --model
            if args.model == DEFAULT_MODEL:
                use_all = detected_all
    else:
        # Live mode - get interface
        interface_name = None
        
        if args.vm:
            # VM mode: auto-select, don't ask user
            interface_name = None
        elif args.interface == 'SELECT' or args.interface is None:
            # Interactive mode: show menu and let user choose
            interface_name = select_interface_interactive()
            if interface_name is None:
                print(f"{COLOR_RED}[MAIN] No interface selected. Exiting.{COLOR_RESET}")
                sys.exit(1)
        else:
            # Explicit interface provided — verify it exists
            interface_name = args.interface
            all_interfaces = list_interfaces()
            iface_names = {iface['name'] for iface in all_interfaces}
            
            if interface_name not in iface_names:
                print(f"{COLOR_RED}[MAIN] Interface not found: {interface_name}{COLOR_RESET}")
                print(f"{COLOR_YELLOW}Available interfaces:{COLOR_RESET}")
                for iface in all_interfaces:
                    print(f"  {iface['name']:<40} {iface['description']}")
                print(f"\n{COLOR_YELLOW}Use --list-interfaces to see all, or omit --interface for interactive selection.{COLOR_RESET}")
                sys.exit(1)

    # Create session ID based on timestamp + model + duration
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    model_code = "all" if use_all else "default"
    mode_code = mode[0].upper()  # L for live, B for batch
    session_id = f"{timestamp}_{model_code}_{mode_code}"
    
    # Create and run session
    session = ClassificationSession(
        mode=mode,
        interface_name=interface_name,
        duration=args.duration,
        use_all_classes=use_all,
        session_id=session_id,
        batch_file_path=batch_file_path,
        has_batch_label=has_batch_label,
        vm_mode=args.vm,
        debug=args.debug,
    )

    # Register SIGINT handler for clean shutdown
    def signal_handler(sig, frame):
        print(f"\n{COLOR_YELLOW}[MAIN] Received signal {sig}. Initiating shutdown...{COLOR_RESET}")
        session.stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    # Start the session
    if not session.start():
        print(f"{COLOR_RED}[MAIN] Failed to start classification session.{COLOR_RESET}")
        sys.exit(1)

    # Wait for duration or Ctrl+C
    session.wait()

    # Session is done (duration reached or user interrupt) - shut everything down
    session.stop()


if __name__ == "__main__":
    main()
