import json
import logging
import sys
from datetime import datetime
from typing import Optional, Dict, Any

from config import LOG_PATH


class StructuredLogger:
    """Simple structured logger for your research workflow."""

    def __init__(self, name: str, log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)

        # Only add handlers if not already added
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)

            # Console handler with colors
            console_handler = logging.StreamHandler(sys.stdout)
            # console_format = '%(asctime)s - %(name)s - \033[%(color)sm%(levelname)s\033[0m - %(message)s'
            console_format = "\033[%(color)sm%(levelname)s\033[0m - %(message)s"
            console_handler.setFormatter(ColoredFormatter(console_format))
            self.logger.addHandler(console_handler)

            # File handler if specified
            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                file_handler.setFormatter(logging.Formatter(file_format))
                self.logger.addHandler(file_handler)

    def log_analysis_step(
        self,
        analysis_id: str,
        step: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Log analysis steps for research tracking."""
        log_data = {
            "analysis_id": analysis_id,
            "step": step,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if details:
            log_data["details"] = details

        if status == "error":
            self.logger.error(f"STEP_FAILED: {json.dumps(log_data)}")
        elif status == "success":
            self.logger.info(f"STEP_SUCCESS: {json.dumps(log_data)}")
        else:
            self.logger.info(f"STEP_INFO: {json.dumps(log_data)}")

    def log_error_generation(self, zone_name: str, error_types: list, success: bool):
        """Log error generation for research tracking."""
        self.logger.info(
            f"ERROR_GEN: zone={zone_name}, errors={len(error_types)}, success={success}"
        )

    def log_fix_attempt(self, zone_name: str, error_code: str, success: bool):
        """Log fix attempts."""
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"FIX_{status}: zone={zone_name}, error={error_code}")


class ColoredFormatter(logging.Formatter):
    """Add colors to console output."""

    COLORS = {
        "DEBUG": "36",  # Cyan
        "INFO": "32",  # Green
        "WARNING": "33",  # Yellow
        "ERROR": "31",  # Red
        "CRITICAL": "35",  # Magenta
    }

    def format(self, record):
        record.color = self.COLORS.get(record.levelname, "0")
        return super().format(record)


# Create a global logger instance for easy use
logger = StructuredLogger("dnssec_analyzer", LOG_PATH)
