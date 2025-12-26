import logging
import json
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from Utils import get_safe_path

class AgentLogger:
    def __init__(self, component: str):
        self.logger = logging.getLogger(f"Jarvis.{component}")
        self.logger.setLevel(logging.INFO)
        log_file = get_safe_path(f"{component}.log", "logs")

        # Hardened Handler: 10MB limit per file, 5 backups max
        handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        self.logger.addHandler(handler)

    def log(self, level: str, event_type: str, metadata: dict):
        """Sanitizes and writes structured JSON logs."""
        # Sanitize metadata to prevent log injection
        clean_meta = {str(k): str(v).replace("\n", " ").replace("\r", " ") 
                     for k, v in metadata.items()}
        
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "data": clean_meta
        }
        
        msg = json.dumps(entry)
        if level.lower() == "warning": self.logger.warning(msg)
        elif level.lower() == "error": self.logger.error(msg)
        else: self.logger.info(msg)