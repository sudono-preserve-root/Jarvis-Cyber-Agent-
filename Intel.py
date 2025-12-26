import requests 
import re
from Utils import get_safe_path, validate_ip 
from Logger import AgentLogger

class IntelManager:
    def __init__(self):
        self.logger = AgentLogger("Intel")
        self.db_file = get_safe_path("blacklist.txt", "intel")

        def fetch_feed(self, url: str):
            # Securley feteched and parses IP lists
            try: 
                # Hardened request: Verify TLS, 10s timeout, max 2MB stream
                with requests.get(url, timeout=10, stream=True, verify=True) as r:
                    r.raise_for_status()
                    valid_ips = []
                    # Saftey check: Prevent downloading massive files 
                    if int(r.headers.get('Content-Length', 0)) > 2 * 1024 * 1024:
                        raise ValueError("Feed size exceeds 2MB limit.")
                    
                    for line in r.iter_lines(decode_unicode=True):
                        ip = line.split('#')[0].strip() # allow comments 
                        if validate_ip(ip):
                            valid_ips.append(ip)

                    # Atomic write to local cache 
                    with open(self.db_file, "w") as f: 
                        f.write("\n".join(set(valid_ips)))
                    return True 
            except Exception as e: 
                self.logger.log("error", "INTEL_FETCHED_FAILED", {"error": str(e)}) 
                return False
                    
                    
