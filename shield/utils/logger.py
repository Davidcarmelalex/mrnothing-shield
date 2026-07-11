"""
Structured logging for MrNothing Shield.

All audit operations are logged with timestamps and integrity
hashes for forensic chain of custody.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def setup_logger(name: str = "shield", log_dir: str = "./logs") -> logging.Logger:
    """Configure structured logger with file and console handlers."""
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    if logger.handlers:
        return logger
    
    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    console.setFormatter(console_format)
    logger.addHandler(console)
    
    # File handler
    log_file = Path(log_dir) / f"shield_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s"
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    return logger


class AuditLogger:
    """
    Forensic audit logger that maintains chain of custody.
    
    Each log entry includes:
    - ISO 8601 timestamp
    - Operation description
    - SHA-256 hash of entry data
    - Previous entry hash (blockchain-style integrity)
    """

    def __init__(self, audit_id: str, log_dir: str = "./logs"):
        self.audit_id = audit_id
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / f"audit_{audit_id}.jsonl"
        self.previous_hash = "0" * 64
        self.logger = setup_logger("shield.audit")

    def log(self, operation: str, data: Dict[str, Any]) -> str:
        """
        Log an audit operation with integrity chain.
        
        Returns:
            Entry hash for verification
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "audit_id": self.audit_id,
            "operation": operation,
            "data": data,
            "previous_hash": self.previous_hash,
        }
        
        # Calculate entry hash
        entry_json = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["entry_hash"] = entry_hash
        
        # Write to log file
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
        
        # Update chain
        self.previous_hash = entry_hash
        
        self.logger.debug(f"Audit log: {operation} [{entry_hash[:8]}]")
        
        return entry_hash

    def verify_chain(self) -> bool:
        """
        Verify integrity of the entire audit chain.
        
        Returns:
            True if chain is valid, False if tampered
        """
        if not self.log_file.exists():
            return True
        
        previous_hash = "0" * 64
        
        with open(self.log_file, "r") as f:
            for line in f:
                entry = json.loads(line.strip())
                
                # Verify previous hash linkage
                if entry.get("previous_hash") != previous_hash:
                    self.logger.error("Audit chain integrity violation detected!")
                    return False
                
                # Verify entry hash
                entry_copy = entry.copy()
                stored_hash = entry_copy.pop("entry_hash")
                calculated_hash = hashlib.sha256(
                    json.dumps(entry_copy, sort_keys=True).encode()
                ).hexdigest()
                
                if stored_hash != calculated_hash:
                    self.logger.error(f"Entry hash mismatch: {stored_hash[:8]}")
                    return False
                
                previous_hash = stored_hash
        
        self.logger.info("Audit chain integrity verified")
        return True
