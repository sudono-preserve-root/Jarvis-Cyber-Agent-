import sys
import os
import time
import json
import signal
import logging
import threading
import platform
from pathlib import Path
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

# --- Safe Imports ---
try:
    import pwd  # UNIX only
except ImportError:
    pwd = None

try:
    from Core import Orchestrator
    from Logger import AgentLogger
    from NetMonitor import NetMonitor
    from Detector import Detector
    from Firewall import Firewall
    from Honeypot import Honeypot
except ImportError as e:
    sys.exit(f"[CRITICAL] Missing Core Modules: {e}")

# --- Constants ---
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
DEFAULT_CONFIG = {
    "system": {"log_level": "INFO", "log_file": "agent.log", "drop_privileges": False, "target_user": "nobody"},
    "firewall": {"dry_run": False, "whitelist": ["127.0.0.1", "::1"]},
    "honeypot": {"enabled": True, "port": 8080},
    "detector": {"sensitivity": "high"}
}

class SentinelAgent:
    """Encapsulated context manager for the Agent lifecycle."""

    def __init__(self):
        self.stop_event = threading.Event()
        self.config = self._load_config()
        self.logger = self._setup_logging()
        self.modules = {}
        self.thread = None

    def _deep_merge(self, defaults, overrides):
        """Recursively updates config to prevent wiping nested default keys."""
        for key, value in overrides.items():
            if isinstance(value, dict) and key in defaults:
                defaults[key] = self._deep_merge(defaults[key], value)
            else:
                defaults[key] = value
        return defaults

    def _load_config(self):
        load_dotenv()
        cfg = DEFAULT_CONFIG.copy()
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH, 'r') as f:
                    self._deep_merge(cfg, json.load(f))
            except (json.JSONDecodeError, PermissionError) as e:
                print(f"[WARN] Config load failed ({e}), using defaults.")
        return cfg

    def _setup_logging(self):
        """Secures log file permissions (600) and sets up rotation."""
        sys_cfg = self.config['system']
        log_path = BASE_DIR / Path(sys_cfg['log_file']).name # Prevent path traversal
        
        # Ensure strict permissions on creation
        if not log_path.exists():
            log_path.touch(mode=0o600)
        else:
            os.chmod(log_path, 0o600)

        handler = RotatingFileHandler(log_path, maxBytes=10*1024*1024, backupCount=5)
        handler.setFormatter(logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s'))
        
        root = logging.getLogger()
        root.setLevel(getattr(logging, sys_cfg['log_level'].upper(), logging.INFO))
        root.addHandler(handler)
        root.addHandler(logging.StreamHandler())
        return logging.getLogger("Sentinel")

    def _drop_privileges(self):
        """Hardened privilege drop: sets groups, GID, then UID."""
        if platform.system() != "Linux" or os.geteuid() != 0:
            return

        target_user = self.config['system']['target_user']
        try:
            pwnam = pwd.getpwnam(target_user)
            log_path = BASE_DIR / self.config['system']['log_file']
            
            # Transfer log ownership before drop
            if log_path.exists():
                os.chown(log_path, pwnam.pw_uid, pwnam.pw_gid)

            # 1. Clear supplementary groups (CRITICAL SECURITY STEP)
            os.setgroups([])
            # 2. Drop GID first
            os.setgid(pwnam.pw_gid)
            # 3. Drop UID last
            os.setuid(pwnam.pw_uid)
            # 4. Set umask for safety
            os.umask(0o077)
            
            self.logger.info(f"SECURITY: Privileges dropped to {target_user} (UID: {os.getuid()})")
        except Exception as e:
            self.logger.critical(f"SECURITY: Failed to drop privileges: {e}")
            sys.exit(1) # Fail closed

    def __enter__(self):
        """Boot sequence."""
        self.logger.info("BOOT: Initializing modules...")
        
        # 1. Initialize Critical Modules
        try:
            self.modules['firewall'] = Firewall(dry_run=self.config['firewall']['dry_run'])
            self.modules['monitor'] = NetMonitor()
            self.modules['detector'] = Detector(self.config['detector'])
            self.modules['logger'] = self.logger

            # 2. Initialize Honeypot (Bind ports before priv drop)
            if self.config['honeypot']['enabled']:
                hp_port = self.config['honeypot']['port']
                self.modules['honeypot'] = Honeypot(bind_port=hp_port)
                self.modules['honeypot'].start()
                self.logger.info(f"MODULE: Honeypot bound to {hp_port}")

            # 3. Security Hardening
            if self.config['system'].get('drop_privileges'):
                self._drop_privileges()

            # 4. Orchestrator
            self.agent = Orchestrator(self.modules)
            
        except Exception as e:
            self.logger.critical(f"BOOT FAILURE: {e}", exc_info=True)
            if 'honeypot' in self.modules: self.modules['honeypot'].stop()
            sys.exit(1)
            
        # Setup Signals
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Graceful shutdown sequence."""
        self.logger.info("SHUTDOWN: Halting modules...")
        self.stop_event.set()
        if 'honeypot' in self.modules:
            self.modules['honeypot'].stop()
        self.logger.info("SHUTDOWN: Complete.")

    def _signal_handler(self, signum, frame):
        self.logger.info(f"SYSTEM: Signal {signum} received.")
        self.stop_event.set()

    def run(self):
        """Main execution loop."""
        self.logger.info("SYSTEM: Active Defense Online.")
        
        # Run orchestrator in separate thread to allow signal handling in main
        self.thread = threading.Thread(target=self.agent.run_main_loop, daemon=True)
        self.thread.start()

        # Efficient wait instead of time.sleep loop
        self.stop_event.wait() 

if __name__ == "__main__":
    with SentinelAgent() as agent:
        agent.run()