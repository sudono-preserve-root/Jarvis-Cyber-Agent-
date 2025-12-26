import subprocess 
import shlex 
import socket 
import logging 
import os
import platform

class Firewall:
    def __init__(self, dry_run=True):
        self.logger = logging.getLogger("Apex.Firewall")
        
        # 1. FIX: Save the dry_run variable so other methods can use it
        self.dry_run = dry_run
        
        # 2. FIX: Detect OS to switch between 'netsh' (Windows) and 'iptables' (Linux)
        self.is_windows = platform.system() == "Windows"
        
        # Hardcoded protection for essential services 
        self.whitelist = {"127.0.0.1", "::1"}
        self._load_current_ip()

    def _load_current_ip(self):
        """Attempts to add current SSH source to whitelist to prevent lockout."""
        # Added safety check for 'SSH_CONNECTION' existence
        if os.getenv('SSH_CONNECTION'):
            ssh_source = os.getenv('SSH_CONNECTION').split(' ')[0]
            if ssh_source:
                self.whitelist.add(ssh_source)

    def validate_ip(self, ip: str) -> bool:
        try: 
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def get_active_rules(self):
        """Returns a list of IPs currently blocked by the agent."""
        if self.is_windows:
            # Windows Logic: List rules matching our naming convention
            cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
            try:
                # We do not use shell=True for security
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                # Parsing logic: Find lines with 'JARVIS_BLOCK_' and extract the IP
                blocked_ips = []
                for line in result.stdout.split('\n'):
                    if "JARVIS_BLOCK_" in line:
                        # Extract "1.2.3.4" from "Rule Name: JARVIS_BLOCK_1.2.3.4"
                        parts = line.split("JARVIS_BLOCK_")
                        if len(parts) > 1:
                            blocked_ips.append(parts[1].strip())
                return blocked_ips
            except Exception as e:
                self.logger.error(f"Failed to fetch Windows rules: {e}")
                return []
        else:
            # Linux Logic (Placeholder for iptables listing if needed)
            return []

    def block_ip(self, ip: str):
        if not self.validate_ip(ip) or ip in self.whitelist:
            self.logger.warning(f"Block ignored: {ip} is invalid or whitelisted.")
            return
        
        # 3. FIX: Switch command based on OS
        if self.is_windows:
            # Windows Command (Netsh)
            rule_name = f"JARVIS_BLOCK_{ip}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", 
                "dir=in", 
                "action=block", 
                f"remoteip={ip}"
            ]
        else:
            # Linux Command (Iptables)
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

        if self.dry_run:
            self.logger.info(f"[DRY-RUN] Block command: {' '.join(cmd)}")
            return
        
        try:
            # Universal subprocess call (works for both OSs)
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.warning(f"Successfully blocked: {ip}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block {ip}: {e.stderr.strip()}")
        except FileNotFoundError:
            self.logger.error(f"Command not found. Ensure {'netsh' if self.is_windows else 'iptables'} is installed.")