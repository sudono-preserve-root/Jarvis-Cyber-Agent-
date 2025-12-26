import logging
import threading
import queue
import time
import psutil
from collections import deque
from scapy.all import sniff, IP, TCP, UDP

class NetMonitor:
    def __init__(self, config=None, max_buffer=1000):
        self.logger = logging.getLogger("Sentinel.Monitor")
        self.config = config if config else {}

        # --- Feature 1: Scapy Packet Sniffer ---
        self.packet_queue = queue.Queue()
        self.running = False
        self.sniffer_thread = None

        # --- Feature 2: Process Connection Monitor ---
        # Resource Guard: maxlen prevents memory exhaustion 
        self.event_buffer = deque(maxlen=max_buffer)
        self.last_scan = 0 
        self.min_interval = 1.0 # Max 1 scan per second 

    def start(self):
        """Starts the packet sniffer in a background thread."""
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()
        self.logger.info("Network Sniffer Started.")

    def stop(self):
        self.running = False
        self.logger.info("Stopping Sniffer...")

    # ==========================================
    # FEATURE 1: Real-Time Packet Sniffing
    # ==========================================
    def get_next_packet(self):
        """Retrieves the next packet from the queue (non-blocking)."""
        try:
            return self.packet_queue.get(block=False)
        except queue.Empty:
            return None

    def _sniff_loop(self):
        """Standard Scapy sniffing loop."""
        try:
            # store=0 prevents RAM explosion (we process packets instantly)
            # filter="ip" ensures we only look at IPv4 traffic
            sniff(prn=self._process_packet, store=0, filter="ip")
        except Exception as e:
            self.logger.critical(f"Sniffer crashed: {e}")

    def _process_packet(self, packet):
        """Callback for every packet captured."""
        if not self.running:
            return

        if IP in packet:
            src_ip = packet[IP].src
            dst_port = 0
            protocol = "OTHER"

            if TCP in packet:
                dst_port = packet[TCP].dport
                protocol = "TCP"
            elif UDP in packet:
                dst_port = packet[UDP].dport
                protocol = "UDP"

            # Create a simplified packet object for the Core
            packet_data = {
                "src_ip": src_ip,
                "port": dst_port,
                "protocol": protocol,
                "size": len(packet)
            }
            
            self.packet_queue.put(packet_data)

    # ==========================================
    # FEATURE 2: Process Telemetry (Psutil)
    # ==========================================
    def get_active_connections(self):
        """Gathers system-wide connection telemetry with rate limiting."""
        now = time.time()
        
        # Rate limit to prevent high CPU usage if called too frequently
        if now - self.last_scan < self.min_interval:
            # Return the last known state if we are scanning too fast
            return list(self.event_buffer)[-1] if self.event_buffer else []
        
        try: 
            # kind='inet' filters for IPv4 and IPv6 connections
            conns = psutil.net_connections(kind='inet')
            self.last_scan = now

            # Extract only essential sanitized data
            current_snapshot = []
            for c in conns:
                if c.raddr:
                    connection_info = {
                        "remote_ip": c.raddr.ip,
                        "remote_port": c.raddr.port,
                        "status": c.status,
                        "pid": c.pid
                    }
                    current_snapshot.append(connection_info)

            self.event_buffer.append(current_snapshot)
            return current_snapshot
        except Exception as e: 
            self.logger.error(f"Telemetry Failure: {e}")
            return []