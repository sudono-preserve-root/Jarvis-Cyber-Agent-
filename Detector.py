import logging
import urllib.request
import threading
import time

class Detector:
    def __init__(self, config=None):
        self.logger = logging.getLogger("Sentinel.Detector")
        self.config = config if config else {}
        self.blacklist = set()
        self.lock = threading.Lock() # Thread safety for async updates
        
        # List of public Threat Intelligence feeds (Plain text IPs)
        self.sources = [
            # Tor Exit Nodes (often used by attackers to hide)
            "https://check.torproject.org/torbulkexitlist",
            # Emerging Threats (Aggregated bad IPs) - Commented out to save bandwidth, uncomment to use
            # "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        ]
        
        # Start fetching Intelligence in the background
        self.refresh_threat_intel()

    def refresh_threat_intel(self):
        """Starts a background thread to download bad IPs."""
        t = threading.Thread(target=self._fetch_feeds, daemon=True)
        t.start()

    def _fetch_feeds(self):
        self.logger.info("DETECTOR: Downloading Threat Intelligence feeds...")
        count = 0
        for url in self.sources:
            try:
                # 5 second timeout to prevent hanging
                with urllib.request.urlopen(url, timeout=5) as response:
                    data = response.read().decode('utf-8')
                    
                    with self.lock:
                        for line in data.splitlines():
                            ip = line.strip()
                            # Basic validation: ensure it looks like an IP and isn't a comment
                            if ip and not ip.startswith('#') and '.' in ip:
                                self.blacklist.add(ip)
                                count += 1
            except Exception as e:
                self.logger.error(f"Failed to fetch feed {url}: {e}")
        
        self.logger.info(f"DETECTOR: Intelligence updated. {len(self.blacklist)} known threats tracked.")

    def scan(self, traffic_data):
        """
        Analyzes traffic. Returns True if the IP is a known threat.
        Expects traffic_data to be a dict: {'src_ip': '1.2.3.4', ...}
        """
        src_ip = traffic_data.get('src_ip')
        
        if not src_ip:
            return False

        # 1. Check against our Threat Intelligence Blacklist
        with self.lock:
            if src_ip in self.blacklist:
                self.logger.warning(f"THREAT MATCH: {src_ip} is on the global blacklist.")
                return True
        
        # 2. (Optional) Future logic for heuristic scanning goes here
        # e.g., if packet size > 10MB, return True
        
        return False