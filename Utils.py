import os
import socket
import logging
from pathlib import Path

def is_root() -> bool:
    """Explicitly check for UID 0 on Linux."""
    try:
        return os.getuid() == 0
    except AttributeError:
        return False

def get_safe_path(requested_path: str, base_subdir: str = "data") -> Path:
    """
    Implements path anchoring to prevent traversal (CWE-22).
    Forces targets to stay within /app/base_subdir/
    """
    base = Path(__file__).resolve().parent / base_subdir
    base.mkdir(exist_ok=True, mode=0o700) # Root-only access by default
    
    # Resolve absolute path and check if it starts with 'base'
    target = (base / requested_path).resolve()
    if not str(target).startswith(str(base)):
        raise PermissionError(f"Security Alert: Path traversal attempt: {requested_path}")
    return target

def validate_ip(ip: str) -> bool:
    """Strict validation for IPv4/IPv6 formats."""
    try:
        if not ip or not isinstance(ip, str): return False
        socket.inet_aton(ip) # IPv4
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip) # IPv6
            return True
        except socket.error:
            return False