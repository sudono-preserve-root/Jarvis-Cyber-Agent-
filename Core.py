import time
import json
import os
import sys
import platform
import ctypes
import logging

class Orchestrator:
    def __init__(self, modules):
        self.logger = logging.getLogger("Sentinel.Core")
        self.modules = modules
        self.firewall = modules.get('firewall')
        self.monitor = modules.get('monitor')
        self.detector = modules.get('detector')
        self.running = True

        # Run startup checks
        self._validate_startup()

    def _validate_startup(self):
        """
        Ensures the agent has sufficient privileges to modify system firewalls.
        Supports both Linux (Root) and Windows (Admin).
        """
        self._log_event("STARTUP_VALIDATION", {"status": "commencing"})
        
        if not self._is_admin():
            # In Dry-Run mode, we can optionally warn instead of crash
            if self.firewall and self.firewall.dry_run:
                self.logger.warning("CORE: Running without privileges (Dry-Run Mode). Firewall actions will fail.")
            else:
                self._log_event("INSUFFICIENT_PRIVILEGES", {"required": "root/admin"})
                raise PermissionError("Orchestrator requires elevated privileges (Run as Admin/Root).")
        
        self.logger.info("CORE: Startup validation passed.")

    def _is_admin(self):
        """Cross-platform check for administrative privileges."""
        try:
            current_os = platform.system()
            if current_os == "Windows":
                # Windows Admin Check
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Linux/Unix Root Check
                return os.geteuid() == 0
        except Exception:
            return False

    def run_main_loop(self):
        """
        The main logic loop. 
        Monitors network, analyzes traffic, and blocks threats.
        """
        self.logger.info("CORE: Orchestrator loop started.")
        
        while self.running:
            try:
                # 1. Get Traffic Data (Placeholder logic)
                # In a real scenario, self.monitor.get_traffic() would return packets
                traffic_sample = {"src_ip": "192.168.1.50", "bytes": 500} 
                
                # 2. Analyze
                if self.detector and self.detector.scan(traffic_sample):
                    target_ip = traffic_sample['src_ip']
                    self.logger.warning(f"THREAT DETECTED: {target_ip}")
                    
                    # 3. Respond
                    if self.firewall:
                        self.firewall.block_ip(target_ip)

                # Sleep to prevent CPU hogging
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"CORE LOOP ERROR: {e}")
                time.sleep(5)

    def _log_event(self, event_type, data):
        """Helper to log structured JSON events."""
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event_type,
            "data": data
        }
        # We use print here to simulate sending to a dashboard/SIEM
        print(json.dumps(entry))