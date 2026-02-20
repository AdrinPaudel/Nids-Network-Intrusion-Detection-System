package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapStat;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * LiveCapture - Headless live network capture that outputs flows to stdout.
 * 
 * Usage:
 *   --list-interfaces          List all available network interfaces
 *   --live <interface_name>    Start live capture on the specified interface
 * 
 * Each completed flow is printed as a CSV line to stdout with the header as the first line.
 * This allows a Python process to read flows in real-time via subprocess pipe.
 */
public class LiveCapture {

    public static final Logger logger = LoggerFactory.getLogger(LiveCapture.class);
    
    private static volatile boolean running = true;
    private static final long FLOW_TIMEOUT = 120000000L;      // 120 seconds in microseconds
    private static final long ACTIVITY_TIMEOUT = 5000000L;    // 5 seconds in microseconds

    // Periodic flow scanner thresholds (real-time output instead of waiting for 120s timeout)
    private static final long IDLE_THRESHOLD  = 15_000_000L;  // 15 seconds in microseconds - emit idle flows
    private static final long AGE_THRESHOLD   = 30_000_000L;  // 30 seconds in microseconds - emit aged flows
    private static final long SCAN_INTERVAL_MS = 10_000L;     // scan every 10 seconds

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            return;
        }

        String command = args[0];
        
        switch (command) {
            case "--list-interfaces":
                listInterfaces();
                break;
            case "--live":
                if (args.length < 2) {
                    System.err.println("ERROR: --live requires an interface name argument");
                    printUsage();
                    System.exit(1);
                }
                String ifName = args[1];
                startLiveCapture(ifName);
                break;
            default:
                System.err.println("ERROR: Unknown command: " + command);
                printUsage();
                System.exit(1);
        }
    }

    private static void printUsage() {
        System.err.println("Usage:");
        System.err.println("  LiveCapture --list-interfaces");
        System.err.println("  LiveCapture --live <interface_name>");
    }

    /**
     * List all available network interfaces in a parseable format.
     * Format: INDEX|NAME|DESCRIPTION|ADDRESSES
     */
    private static void listInterfaces() {
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> allDevs = new ArrayList<>();
        
        int result = Pcap.findAllDevs(allDevs, errbuf);
        if (result != Pcap.OK || allDevs.isEmpty()) {
            System.err.println("ERROR: Could not find network interfaces: " + errbuf.toString());
            System.exit(1);
        }

        // Print header
        System.out.println("INDEX|NAME|DESCRIPTION|ADDRESSES");
        
        for (int i = 0; i < allDevs.size(); i++) {
            PcapIf dev = allDevs.get(i);
            String name = dev.getName();
            String description = dev.getDescription() != null ? dev.getDescription() : "N/A";
            
            // Collect addresses
            StringBuilder addrs = new StringBuilder();
            if (dev.getAddresses() != null && !dev.getAddresses().isEmpty()) {
                for (int j = 0; j < dev.getAddresses().size(); j++) {
                    if (j > 0) addrs.append(";");
                    try {
                        byte[] addrBytes = dev.getAddresses().get(j).getAddr().getData();
                        if (addrBytes.length == 4) {
                            // IPv4
                            addrs.append(String.format("%d.%d.%d.%d", 
                                addrBytes[0] & 0xFF, addrBytes[1] & 0xFF, 
                                addrBytes[2] & 0xFF, addrBytes[3] & 0xFF));
                        }
                    } catch (Exception e) {
                        // Skip malformed addresses
                    }
                }
            }
            if (addrs.length() == 0) addrs.append("N/A");
            
            System.out.println(i + "|" + name + "|" + description + "|" + addrs.toString());
        }
        System.out.flush();
    }

    /**
     * Start live packet capture on the specified interface.
     * Outputs the CSV header first, then each flow as a CSV line to stdout.
     * Monitors stdin for "STOP" command to trigger graceful shutdown with flow dump.
     *
     * Uses pcap.nextEx() in a manual polling loop instead of pcap.loop()/dispatch().
     * The JNI callback mechanism in jNetPcap 1.4 has an issue on Windows/Npcap where
     * the handler callback is never invoked despite pcap_recv counting packets at the
     * driver level. pcap.nextEx() bypasses this entirely by reading packets directly,
     * matching the approach used by the original CICFlowMeter PacketReader for offline
     * pcap files. This is proven to work reliably (tested: 3600+ packets in 15 seconds).
     */
    private static void startLiveCapture(String interfaceName) {
        // Register shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            running = false;
            System.err.println("SHUTDOWN: Stopping capture...");
        }));

        // Find the interface
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> allDevs = new ArrayList<>();
        int result = Pcap.findAllDevs(allDevs, errbuf);
        if (result != Pcap.OK || allDevs.isEmpty()) {
            System.err.println("ERROR: Could not find network interfaces: " + errbuf.toString());
            System.exit(1);
        }

        PcapIf selectedDev = null;
        for (PcapIf dev : allDevs) {
            if (dev.getName().equals(interfaceName)) {
                selectedDev = dev;
                break;
            }
        }

        if (selectedDev == null) {
            System.err.println("ERROR: Interface not found: " + interfaceName);
            System.err.println("Available interfaces:");
            for (PcapIf dev : allDevs) {
                System.err.println("  " + dev.getName() + " - " + 
                    (dev.getDescription() != null ? dev.getDescription() : "N/A"));
            }
            System.exit(1);
        }

        System.err.println("INFO: Opening interface: " + interfaceName);
        
        // Print CSV header to stdout FIRST
        System.out.println(FlowFeature.getHeader());
        System.out.flush();

        // Create flow generator
        FlowGenerator flowGen = new FlowGenerator(true, FLOW_TIMEOUT, ACTIVITY_TIMEOUT);

        // Packet counters for diagnostics
        long packetCount = 0;
        long validPacketCount = 0;
        
        // Add listener that prints each flow to stdout (thread-safe: called under FlowGenerator lock)
        flowGen.addFlowListener(new FlowGenListener() {
            private long flowCount = 0;

            @Override
            public void onFlowGenerated(BasicFlow flow) {
                if (flow.packetCount() > 1) {
                    String flowLine = flow.dumpFlowBasedFeaturesEx();
                    synchronized (System.out) {
                        System.out.println(flowLine);
                        System.out.flush();
                    }
                    
                    flowCount++;
                    if (flowCount % 50 == 0) {
                        System.err.println("INFO: " + flowCount + " flows emitted so far");
                    }
                }
            }
        });

        // ================================================================
        // OPEN PCAP
        // ================================================================
        int snaplen = 64 * 1024;
        int timeout = 1000;  // 1 second read timeout for nextEx (returns quickly)
        
        Pcap pcap = openPcapWithFallback(selectedDev, snaplen, timeout, errbuf);
        if (pcap == null) {
            System.err.println("ERROR: Failed to open interface with any mode. Exiting.");
            System.exit(1);
        }

        System.err.println("READY: Listening on " + interfaceName);
        System.err.flush();

        // ================================================================
        // START HELPER THREADS
        // ================================================================
        
        final Pcap pcapRef = pcap;

        // Start stdin monitor thread - sets running=false on STOP command
        Thread stdinMonitor = new Thread(() -> {
            try {
                java.io.BufferedReader stdinReader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(System.in));
                while (running) {
                    if (stdinReader.ready()) {
                        String line = stdinReader.readLine();
                        if (line != null && line.trim().equalsIgnoreCase("STOP")) {
                            System.err.println("INFO: Received STOP command via stdin");
                            running = false;
                            break;
                        }
                    }
                    Thread.sleep(100);
                }
            } catch (Exception e) {
                // stdin closed or interrupted
            }
        }, "stdin-monitor");
        stdinMonitor.setDaemon(true);
        stdinMonitor.start();

        // Scanner thread - emits idle/aged flows and reports stats periodically
        // packetCount and validPacketCount are tracked via final array for thread access
        final long[] counters = {0, 0};  // [0]=packets, [1]=valid
        Thread scannerThread = new Thread(() -> {
            try {
                Thread.sleep(SCAN_INTERVAL_MS);
                while (running) {
                    long nowMicros = System.currentTimeMillis() * 1000L;
                    int emitted = flowGen.emitIdleAndAgedFlows(nowMicros, IDLE_THRESHOLD, AGE_THRESHOLD);
                    int activeFlows = flowGen.getCurrentFlowCount();
                    
                    System.err.println("SCAN: packets=" + counters[0] + 
                        " valid=" + counters[1] +
                        " emitted=" + emitted + 
                        " active_flows=" + activeFlows);
                    System.err.flush();
                    Thread.sleep(SCAN_INTERVAL_MS);
                }
            } catch (InterruptedException e) {
                // Expected on shutdown
            }
        }, "flow-scanner");
        scannerThread.setDaemon(true);
        scannerThread.start();

        // ================================================================
        // MAIN CAPTURE LOOP - using pcap.nextEx() polling
        // ================================================================
        // pcap.nextEx() reads one packet at a time, same approach as PacketReader.
        // This bypasses the broken JNI callback mechanism (loop/dispatch) and reads
        // packets directly. Proven to work: 3600+ packets/15s in testing.
        System.err.println("INFO: Capture starting. Flow timeout=" + (FLOW_TIMEOUT/1000000) + "s" +
            ", Idle threshold=" + (IDLE_THRESHOLD/1000000) + "s" +
            ", Age threshold=" + (AGE_THRESHOLD/1000000) + "s" +
            ", Scan interval=" + (SCAN_INTERVAL_MS/1000) + "s" +
            ", Pcap timeout=" + timeout + "ms" +
            ", Mode=nextEx-poll");
        System.err.flush();

        // Reusable header and buffer objects (same pattern as PacketReader)
        PcapHeader hdr = new PcapHeader(JMemory.POINTER);
        JBuffer buf = new JBuffer(JMemory.POINTER);

        while (running) {
            int ret = pcap.nextEx(hdr, buf);
            
            if (ret == Pcap.NEXT_EX_OK) {
                packetCount++;
                counters[0] = packetCount;
                
                try {
                    // Create packet and scan for Ethernet frame (same as PacketReader)
                    PcapPacket packet = new PcapPacket(hdr, buf);
                    packet.scan(Ethernet.ID);
                    
                    BasicPacketInfo packetInfo = PacketReader.getBasicPacketInfo(packet, true, false);
                    if (packetInfo != null) {
                        flowGen.addPacket(packetInfo);
                        validPacketCount++;
                        counters[1] = validPacketCount;
                    }
                } catch (Exception e) {
                    if (packetCount <= 3) {
                        System.err.println("WARNING: Packet parse error #" + packetCount + ": " + e.getMessage());
                    }
                }
                
                // Log first few packets for debugging
                if (packetCount <= 3) {
                    System.err.println("INFO: Packet #" + packetCount + " captured, caplen=" + hdr.caplen());
                }
                if (packetCount == 10) {
                    System.err.println("INFO: 10 packets captured. valid=" + validPacketCount + ". Capture working!");
                }

            } else if (ret == Pcap.NEXT_EX_TIMEDOUT) {
                // Timeout (no packets in the timeout period), just continue
                continue;
            } else if (ret == Pcap.NEXT_EX_EOF) {
                System.err.println("INFO: EOF on capture (live capture shouldn't get this)");
                break;
            } else {
                // Error
                System.err.println("ERROR: pcap.nextEx error (ret=" + ret + "): " + pcap.getErr());
                break;
            }
        }

        // ================================================================
        // SHUTDOWN
        // ================================================================
        running = false;
        scannerThread.interrupt();
        try { scannerThread.join(5000); } catch (InterruptedException e) { }

        System.err.println("INFO: Capture loop ended." +
            " Packets=" + packetCount + 
            " valid=" + validPacketCount +
            ". Dumping remaining flows...");
        dumpRemainingFlows(flowGen);
        
        pcap.close();
        System.err.println("DONE: Capture complete. Packets=" + packetCount + " valid=" + validPacketCount);
        System.err.flush();
    }

    /**
     * Open pcap trying promiscuous first, then non-promiscuous.
     * Some WiFi drivers on Windows silently fail with promiscuous mode.
     */
    private static Pcap openPcapWithFallback(PcapIf dev, int snaplen, int timeout, StringBuilder errbuf) {
        // Try promiscuous mode first
        Pcap pcap = Pcap.openLive(dev.getName(), snaplen, Pcap.MODE_PROMISCUOUS, timeout, errbuf);
        if (pcap != null) {
            System.err.println("INFO: Opened interface in PROMISCUOUS mode (timeout=" + timeout + "ms)");
            return pcap;
        }
        
        System.err.println("WARNING: Promiscuous mode failed: " + errbuf.toString());
        System.err.println("INFO: Trying non-promiscuous mode...");
        errbuf.setLength(0);
        
        pcap = Pcap.openLive(dev.getName(), snaplen, Pcap.MODE_NON_PROMISCUOUS, timeout, errbuf);
        if (pcap != null) {
            System.err.println("INFO: Opened interface in NON-PROMISCUOUS mode");
            return pcap;
        }
        
        System.err.println("ERROR: Non-promiscuous mode also failed: " + errbuf.toString());
        return null;
    }

    /**
     * Dump all remaining in-progress flows to stdout.
     * Uses emitIdleAndAgedFlows with threshold=0 to emit everything through the listener.
     * Falls back to temp file approach if that fails.
     */
    private static void dumpRemainingFlows(FlowGenerator flowGen) {
        try {
            // Use the scanner method with threshold 0 → emits ALL remaining flows
            // through the listener (which prints to stdout). Much simpler and more
            // reliable than the old temp-file approach.
            long nowMicros = System.currentTimeMillis() * 1000L;
            int count = flowGen.emitIdleAndAgedFlows(nowMicros, 0, 0);
            System.out.flush();
            if (count > 0) {
                System.err.println("INFO: Dumped " + count + " remaining flows via listener");
            } else {
                System.err.println("INFO: No remaining flows to dump (all already emitted)");
            }
        } catch (Exception e) {
            System.err.println("ERROR: Failed to dump remaining flows: " + e.getMessage());
            // Fallback: try the temp file approach
            try {
                java.io.File tempFile = java.io.File.createTempFile("cicflow_remaining_", ".csv");
                tempFile.deleteOnExit();
                tempFile.delete();
                long count = flowGen.dumpLabeledCurrentFlow(tempFile.getAbsolutePath(), FlowFeature.getHeader());
                if (count > 0) {
                    java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(tempFile));
                    String line;
                    boolean firstLine = true;
                    while ((line = reader.readLine()) != null) {
                        if (firstLine) { firstLine = false; continue; }
                        System.out.println(line);
                    }
                    reader.close();
                    System.out.flush();
                    System.err.println("INFO: Dumped " + count + " remaining flows via temp file (fallback)");
                }
                tempFile.delete();
            } catch (Exception e2) {
                System.err.println("ERROR: Fallback dump also failed: " + e2.getMessage());
            }
        }
    }
}
