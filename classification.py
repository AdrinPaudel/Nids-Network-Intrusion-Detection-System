#!/usr/bin/env python
"""
NIDS Classification - Live Traffic Analysis
============================================

Main orchestrator for real-time network traffic classification.

Starts a multi-threaded pipeline:
    CICFlowMeter Source → Preprocessor → Classifier → Threat Handler + Report Generator

Each component runs in its own thread with queues connecting them.

Usage:
    python classification.py                     # Live capture, WiFi auto-detect, 180s
    python classification.py --duration 300      # Live capture for 5 minutes
    python classification.py --model all         # Use 'all' model (with Infilteration)
    python classification.py --interface "..."   # Specify network interface
    python classification.py --list-interfaces   # List available interfaces

Multiple instances can run simultaneously without interfering with each other.
"""

import os
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning"
import sys
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=ResourceWarning, message="subprocess")
import argparse
import threading
import queue
import time
import signal

# ============================================================
# VENV CHECK - Verify virtual environment is active
# ============================================================
def check_venv():
    """Check that required packages are importable; exit if not."""
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
        print("\nSetup your environment first:\n")
        print("  1. Create a virtual environment (if not already):")
        print("       python -m venv venv\n")
        print("  2. Activate it:")
        if sys.platform.startswith('win'):
            print("       venv\\Scripts\\activate")
        else:
            print("       source venv/bin/activate")
        print("\n  3. Install dependencies:")
        print("       pip install -r requirements.txt\n")
        print("  4. Run again:")
        print("       python classification.py\n")
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
from classification.cicflowmeter_source import (
    CICFlowMeterSource, list_interfaces, 
    get_wifi_interfaces, get_ethernet_interfaces
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
                 use_all_classes=False, csv_path=None, session_id=1, batch_file_path=None, has_batch_label=False):
        """
        Args:
            mode: 'live', 'batch', 'csv', or 'simul' (only 'live' and 'batch' implemented)
            interface_name: network interface device name (None = auto-detect WiFi) [for live mode]
            duration: capture duration in seconds [for live mode]
            use_all_classes: use 'all' model if True
            csv_path: path to CSV file (for csv mode)
            session_id: unique session identifier
            batch_file_path: path to batch CSV file (for batch mode)
            has_batch_label: if True, batch file has actual labels
        """
        self.mode = mode
        self.interface_name = interface_name
        self.duration = duration
        self.use_all_classes = use_all_classes
        self.csv_path = csv_path
        self.session_id = session_id
        self.batch_file_path = batch_file_path
        self.has_batch_label = has_batch_label

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
                wifi_ifaces = get_wifi_interfaces(interfaces)
                eth_ifaces = get_ethernet_interfaces(interfaces)
                
                if wifi_ifaces:
                    self.interface_name = wifi_ifaces[0]['name']
                    print(f"{COLOR_CYAN}[SESSION] Auto-selected WiFi interface: {self.interface_name}{COLOR_RESET}")
                elif eth_ifaces:
                    self.interface_name = eth_ifaces[0]['name']
                    print(f"{COLOR_CYAN}[SESSION] Auto-selected Ethernet interface: {self.interface_name}{COLOR_RESET}")
                else:
                    print(f"{COLOR_RED}[SESSION] No network interfaces available!{COLOR_RESET}")
                    return False
            
            return self._start_live()
        elif self.mode == "batch":
            return self._start_batch()
        elif self.mode == "csv":
            print("\033[93m[SESSION] CSV mode not yet implemented.\033[0m")
            return False
        elif self.mode == "simul":
            print("\033[93m[SESSION] Simulation mode not yet implemented.\033[0m")
            return False
        else:
            print(f"\033[91m[SESSION] Unknown mode: {self.mode}\033[0m")
            return False

    def _start_live(self):
        """Start the live capture pipeline."""

        # 1. Create CICFlowMeter source
        self.source = CICFlowMeterSource(
            flow_queue=self.flow_queue,
            interface_name=self.interface_name,
            stop_event=self.stop_event,
        )

        # 2. Create preprocessor
        self.preprocessor = Preprocessor(
            flow_queue=self.flow_queue,
            classifier_queue=self.classifier_queue,
            stop_event=self.stop_event,
            use_all_classes=self.use_all_classes,
            mode=self.mode,
        )

        # 3. Create classifier
        self.classifier = Classifier(
            classifier_queue=self.classifier_queue,
            threat_queue=self.threat_queue,
            report_queue=self.report_queue,
            stop_event=self.stop_event,
            use_all_classes=self.use_all_classes,
            mode=self.mode,
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

        # Start CICFlowMeter source (subprocess, not a thread itself - has internal threads)
        if not self.source.start():
            print(f"{COLOR_RED}[SESSION] Failed to start CICFlowMeter source.{COLOR_RESET}")
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

        print(f"{COLOR_GREEN}[SESSION] Pipeline started with {len(self.threads)} threads + CICFlowMeter subprocess{COLOR_RESET}")
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
                        header_ok = "yes" if (self.source and self.source._header_received.is_set()) else "no"
                        java_alive = "yes" if (self.source and self.source.is_alive()) else "no"
                        print(f"{COLOR_DARK_GRAY}[SESSION] {int(elapsed)}s elapsed | "
                              f"Java alive: {java_alive} | Header: {header_ok} | "
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
        THREAD_JOIN_TIMEOUT = 30

        print(f"\n{COLOR_CYAN}[SESSION] Shutting down session {self.session_id}...{COLOR_RESET}")

        # ── Step 1: Stop the source (Java subprocess) ──────────────────────
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
    
    # Create a flat list with all interfaces
    all_ifaces = []
    
    print(f"\n{COLOR_CYAN}Available Interfaces:{COLOR_RESET}\n")
    
    idx = 1
    if wifi_ifaces:
        print(f"{COLOR_CYAN_BOLD}WiFi Adapters:{COLOR_RESET}")
        for iface in wifi_ifaces:
            print(f"  [{idx}] {iface['description']}")
            print(f"      Address: {iface['addresses']}")
            all_ifaces.append(iface)
            idx += 1
    else:
        print(f"{COLOR_YELLOW}(No WiFi adapters found){COLOR_RESET}")
    
    if ethernet_ifaces:
        print(f"\n{COLOR_CYAN_BOLD}Ethernet Adapters:{COLOR_RESET}")
        for iface in ethernet_ifaces:
            print(f"  [{idx}] {iface['description']}")
            print(f"      Address: {iface['addresses']}")
            all_ifaces.append(iface)
            idx += 1
    else:
        print(f"{COLOR_YELLOW}(No Ethernet adapters found){COLOR_RESET}")
    
    print(f"\n{COLOR_CYAN}{'='*80}{COLOR_RESET}")
    
    # Prompt user
    while True:
        try:
            choice = input(f"\n{COLOR_CYAN_BOLD}Enter interface number (1-{len(all_ifaces)}){COLOR_RESET}: ").strip()
            choice_idx = int(choice) - 1
            
            if 0 <= choice_idx < len(all_ifaces):
                selected = all_ifaces[choice_idx]
                print(f"\n{COLOR_GREEN}✓ Selected: {selected['description']}{COLOR_RESET}\n")
                return selected['name']
            else:
                print(f"{COLOR_RED}Invalid choice. Please enter a number between 1 and {len(all_ifaces)}.{COLOR_RESET}")
        except (ValueError, IndexError):
            print(f"{COLOR_RED}Invalid input. Please enter a number.{COLOR_RESET}")
        except EOFError:
            # Running in headless mode - auto-select Ethernet, fallback to WiFi
            print(f"\n{COLOR_YELLOW}EOF detected - auto-selecting interface...{COLOR_RESET}")
            if ethernet_ifaces:
                selected = ethernet_ifaces[0]
                print(f"{COLOR_GREEN}[OK] Auto-selected: {selected['description']}{COLOR_RESET}\n")
                return selected['name']
            elif wifi_ifaces:
                selected = wifi_ifaces[0]
                print(f"{COLOR_GREEN}[OK] Auto-selected: {selected['description']}{COLOR_RESET}\n")
                return selected['name']
            else:
                print(f"{COLOR_RED}No network interfaces available!{COLOR_RESET}")
                return None


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
  python classification.py --batch                  # Batch mode (select CSV file)
  python classification.py --batch data/batch/file.csv  # Batch mode with specific file
        """
    )

    parser.add_argument(
        "--mode", choices=["live", "batch", "csv", "simul"], default="live",
        help="Classification mode (default: live)"
    )
    parser.add_argument(
        "--batch", type=str, nargs='?', const='SELECT',
        help="Batch mode: optionally specify CSV file path (default: interactive selection)"
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
        "--interface", type=str, default=None,
        help="Network interface device name (default: interactive selection)"
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List available network interfaces and exit"
    )
    parser.add_argument(
        "--csv", type=str, default=None,
        help="Path to CSV file for csv mode (not yet implemented)"
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
        interface_name = args.interface
        if interface_name is None:
            interface_name = select_interface_interactive()
            if interface_name is None:
                print(f"{COLOR_RED}[MAIN] No interface selected. Exiting.{COLOR_RESET}")
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
        csv_path=args.csv,
        session_id=session_id,
        batch_file_path=batch_file_path,
        has_batch_label=has_batch_label,
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
