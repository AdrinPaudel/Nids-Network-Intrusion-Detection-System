"""
Threat Handler
Reads classification results and displays threats in the terminal.

Threat levels:
    RED   - Highest confidence class is an attack → CONFIRMED THREAT
    YELLOW - Highest is not attack, but 2nd highest has confidence > 25% → SUSPICIOUS
    GREEN  - All clear → only logged, not displayed

Only RED and YELLOW are displayed in terminal.
"""

import os
import sys
import threading
import queue
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_BENIGN_CLASS, CLASSIFICATION_SUSPICIOUS_THRESHOLD,
    CLASSIFICATION_QUEUE_TIMEOUT, CLASSIFICATION_THREAT_DISPLAY_WIDTH,
    COLOR_RED, COLOR_RED_BOLD, COLOR_YELLOW,
    COLOR_YELLOW_BOLD, COLOR_GREEN, COLOR_RESET
)

# Backward compatibility aliases
BENIGN_CLASS = CLASSIFICATION_BENIGN_CLASS
SUSPICIOUS_THRESHOLD = CLASSIFICATION_SUSPICIOUS_THRESHOLD


class ThreatHandler:
    """
    Real-time threat handler that reads classification results
    and displays alerts in the terminal.
    """

    def __init__(self, threat_queue, stop_event):
        """
        Args:
            threat_queue: queue.Queue of classification result dicts
            stop_event: threading.Event to signal stop
        """
        self.threat_queue = threat_queue
        self.stop_event = stop_event
        self.red_count = 0
        self.yellow_count = 0
        self.green_count = 0
        self.total_count = 0

    def _assess_threat(self, result):
        """
        Assess threat level from classification result.

        Args:
            result: dict with 'top3', 'identifiers', 'predicted_class', 'confidence'

        Returns:
            'RED', 'YELLOW', or 'GREEN'
        """
        top3 = result["top3"]
        top_class = top3[0][0]
        top_conf = top3[0][1]

        # If highest confidence is an attack (not Benign) → RED
        if top_class != BENIGN_CLASS:
            return "RED"

        # Highest is Benign. Check 2nd highest confidence
        if len(top3) >= 2:
            second_class = top3[1][0]
            second_conf = top3[1][1]

            if second_class != BENIGN_CLASS and second_conf >= SUSPICIOUS_THRESHOLD:
                return "YELLOW"

        return "GREEN"

    def _format_identifiers(self, identifiers):
        """Format flow identifiers for display."""
        src_ip = identifiers.get("Src IP", "?")
        dst_ip = identifiers.get("Dst IP", "?")
        src_port = identifiers.get("Src Port", "?")
        dst_port = identifiers.get("Dst Port", "?")
        protocol = identifiers.get("Protocol", "?")
        return f"{src_ip}:{src_port} → {dst_ip}:{dst_port} (Proto:{protocol})"

    def _display_red(self, result):
        """Display a RED (confirmed threat) alert."""
        top3 = result["top3"]
        ids = self._format_identifiers(result["identifiers"])
        ts = result["timestamp"]

        print(f"\n{COLOR_RED}{'='*CLASSIFICATION_THREAT_DISPLAY_WIDTH}{COLOR_RESET}")
        print(f"{COLOR_RED_BOLD}  ⚠  THREAT DETECTED  ⚠   [{ts}]{COLOR_RESET}")
        print(f"{COLOR_RED}{'='*CLASSIFICATION_THREAT_DISPLAY_WIDTH}{COLOR_RESET}")
        print(f"{COLOR_RED}  Flow: {ids}{COLOR_RESET}")
        print(f"{COLOR_RED_BOLD}  Attack: {top3[0][0]}  (Confidence: {top3[0][1]*100:.1f}%){COLOR_RESET}")
        if len(top3) >= 2:
            print(f"{COLOR_RED}  2nd:    {top3[1][0]}  ({top3[1][1]*100:.1f}%){COLOR_RESET}")
        if len(top3) >= 3:
            print(f"{COLOR_RED}  3rd:    {top3[2][0]}  ({top3[2][1]*100:.1f}%){COLOR_RESET}")
        print(f"{COLOR_RED}{'='*CLASSIFICATION_THREAT_DISPLAY_WIDTH}{COLOR_RESET}\n")

    def _display_yellow(self, result):
        """Display a YELLOW (suspicious) alert."""
        top3 = result["top3"]
        ids = self._format_identifiers(result["identifiers"])
        ts = result["timestamp"]

        print(f"\n{COLOR_YELLOW}{'-'*CLASSIFICATION_THREAT_DISPLAY_WIDTH}{COLOR_RESET}")
        print(f"{COLOR_YELLOW_BOLD}  ⚡ SUSPICIOUS ACTIVITY  [{ts}]{COLOR_RESET}")
        print(f"{COLOR_YELLOW}{'-'*CLASSIFICATION_THREAT_DISPLAY_WIDTH}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}  Flow: {ids}{COLOR_RESET}")
        print(f"{COLOR_YELLOW}  Top:  {top3[0][0]}  ({top3[0][1]*100:.1f}%){COLOR_RESET}")
        if len(top3) >= 2:
            print(f"{COLOR_YELLOW_BOLD}  2nd:  {top3[1][0]}  ({top3[1][1]*100:.1f}%)  ← suspicious{COLOR_RESET}")
        if len(top3) >= 3:
            print(f"{COLOR_YELLOW}  3rd:  {top3[2][0]}  ({top3[2][1]*100:.1f}%){COLOR_RESET}")
        print(f"{COLOR_YELLOW}{'-'*CLASSIFICATION_THREAT_DISPLAY_WIDTH}{COLOR_RESET}\n")

    def run(self):
        """Main loop: read from threat_queue and display alerts.
        Runs until a None sentinel is received from the classifier."""
        print(f"{COLOR_GREEN}[THREAT-HANDLER] Started. Monitoring for threats...{COLOR_RESET}")

        while True:
            try:
                result = self.threat_queue.get(timeout=CLASSIFICATION_QUEUE_TIMEOUT)

                # Sentinel: end of pipeline input
                if result is None:
                    self.threat_queue.task_done()
                    break

                self.total_count += 1

                threat_level = self._assess_threat(result)

                if threat_level == "RED":
                    self.red_count += 1
                    self._display_red(result)
                elif threat_level == "YELLOW":
                    self.yellow_count += 1
                    self._display_yellow(result)
                else:
                    self.green_count += 1

                self.threat_queue.task_done()

            except queue.Empty:
                if self.stop_event.is_set():
                    break
                continue
            except Exception as e:
                print(f"{COLOR_RED}[THREAT-HANDLER] Error: {e}{COLOR_RESET}")

        # Drain remaining
        while not self.threat_queue.empty():
            try:
                result = self.threat_queue.get_nowait()
                if result is None:
                    self.threat_queue.task_done()
                    continue
                self.total_count += 1
                threat_level = self._assess_threat(result)
                if threat_level == "RED":
                    self.red_count += 1
                    self._display_red(result)
                elif threat_level == "YELLOW":
                    self.yellow_count += 1
                    self._display_yellow(result)
                else:
                    self.green_count += 1
                self.threat_queue.task_done()
            except queue.Empty:
                break

        print(f"\n{COLOR_GREEN}[THREAT-HANDLER] Session Summary:{COLOR_RESET}")
        print(f"  {COLOR_RED}RED (Threats):     {self.red_count}{COLOR_RESET}")
        print(f"  {COLOR_YELLOW}YELLOW (Suspicious): {self.yellow_count}{COLOR_RESET}")
        print(f"  {COLOR_GREEN}GREEN (Clean):     {self.green_count}{COLOR_RESET}")
        print(f"  Total flows:       {self.total_count}")
