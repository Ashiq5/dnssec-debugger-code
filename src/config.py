import os
from pathlib import Path
from typing import List
from pathlib import Path


class Config:
    """Centralized configuration for DSECTwist Docker deployment."""

    # Core settings
    TTL = 30
    AUTH_SOFTWARE = "BIND"
    HAVE_SECONDARY_ZONE = True
    APPLY_FIX = True

    # Domain and DNS
    DOMAIN = "erroneouszonegeneration.ovh."
    NS1 = "ns1.erroneouszonegeneration.ovh."
    NS2 = "ns2.erroneouszonegeneration.ovh."
    NS3 = "ns3.erroneouszonegeneration.ovh."
    NS4 = "ns4.erroneouszonegeneration.ovh."

    # Network
    IP_1 = "129.88.71.95"
    IP_2 = "129.88.71.96"
    SERVER = IP_1

    # Nameserver assignments
    ROOT_NS = [NS1, NS2]
    PARENT_NS = [NS1, NS2]
    CHILD_NS = [NS1, NS3]

    # Docker paths
    WORKING_PATH = "/data/ErroneousZoneGeneration/"
    BASE_KEY_DIR = "/data/bind1/keys/"
    X3LD_KEY_DIR = "/data/bind1/keys/randomly_generated/"

    # Primary bind server paths
    ZONE_DIR = "/data/bind1/zones/"
    ZONE_CONF_FILE = "/data/bind1/named.conf.local"
    SERVER_ZONE_DIR = "/data/bind1/zones/"

    # Secondary bind server paths  
    ZONE_DIR_SECOND_NS = "/data/bind2/zones/"
    ZONE_CONF_FILE_SECONDARY_NS = "/data/bind2/named.conf.local"
    SERVER_ZONE_DIR_SECOND_NS = "/data/bind2/zones/"
    SERVER_ZONE_CONF_DIR_SECOND_NS = "/data/bind2/"
    SERVER_KEY_DIR_SECOND_NS = "/data/bind2/keys/"
    SERVER_ZONE_CONF_PATH_SECOND_NS = f"{SERVER_ZONE_CONF_DIR_SECOND_NS}named.conf.local"

    # DNSSEC defaults
    DEFAULT_SALT = "8D4557157F54153F"
    DEFAULT_EXPIRATION = "20260306224643"
    DEFAULT_INCEPTION = "20250319195202"

    # Analysis and output
    CASE = "analysis-docker"
    OUTPUT_FILE = "/data/ErroneousZoneGeneration/tmp/test-results/main.txt"
    INSTRUCTION_PATH = "/data/ErroneousZoneGeneration/tmp/instructions.txt"
    BATCH_GROK_PATH = "/data/ErroneousZoneGeneration/.local/dnsviz-small.input"
    INPUT_GROK_PATH = "/data/ErroneousZoneGeneration/tmp/input-grok.json"
    RESOLVE_GROK_PATH = "/tmp/resolve-grok.json"
    GENERATED_GROK_PATH = "/data/ErroneousZoneGeneration/tmp/generated-grok.json"
    LOG_PATH = "/data/ErroneousZoneGeneration/tmp/logs/dnssec_analysis.log"
    # DNSViz analysis command
    DNSVIZ_ANALYSIS_CMD = (
        f"dnsviz probe -A -a {CASE}.{DOMAIN} -x {DOMAIN}:{IP_1} "
        f"<name> <extra_args> | dnsviz grok -o {GENERATED_GROK_PATH}"
    )
    NSEC3_KEY_NOT_USED_PATH = "/tmp/nsec3-key-not-used.txt"
    @classmethod
    def validate(cls) -> None:
        """Validate configuration and create necessary directories."""
        # Ensure required directories exist
        directories = [
            cls.WORKING_PATH,
            cls.BASE_KEY_DIR,
            cls.X3LD_KEY_DIR,
            cls.ZONE_DIR,
            cls.ZONE_DIR_SECOND_NS,
            Path(cls.BATCH_GROK_PATH).parent,
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

        # Validate domain format
        if not cls.DOMAIN.endswith('.'):
            raise ValueError("DOMAIN must end with '.'")

        # Validate nameservers
        for ns in [cls.NS1, cls.NS2, cls.NS3, cls.NS4]:
            if not ns.endswith('.'):
                raise ValueError(f"Nameserver {ns} must end with '.'")

    @classmethod
    def get_environment_info(cls) -> dict:
        """Get current environment information for debugging."""
        return {
            "domain": cls.DOMAIN,
            "primary_server": cls.SERVER,
            "nameservers": {
                "root": cls.ROOT_NS,
                "parent": cls.PARENT_NS,
                "child": cls.CHILD_NS,
            },
            "paths": {
                "working": cls.WORKING_PATH,
                "zones": cls.ZONE_DIR,
                "keys": cls.BASE_KEY_DIR,
            }
        }


# For backwards compatibility, expose the main values at module level
# This allows existing code to import these directly without changing imports

# Domain and DNS
DOMAIN = Config.DOMAIN
TTL = Config.TTL
NS1 = Config.NS1
NS2 = Config.NS2
NS3 = Config.NS3
NS4 = Config.NS4
ROOT_NS = Config.ROOT_NS
PARENT_NS = Config.PARENT_NS
CHILD_NS = Config.CHILD_NS

# Network
SERVER = Config.SERVER
IP_1 = Config.IP_1
IP_2 = Config.IP_2
RESOLVE_GROK_PATH = Config.RESOLVE_GROK_PATH
# DNSSEC
DEFAULT_SALT = Config.DEFAULT_SALT
DEFAULT_EXPIRATION = Config.DEFAULT_EXPIRATION
DEFAULT_INCEPTION = Config.DEFAULT_INCEPTION

# Settings
AUTH_SOFTWARE = Config.AUTH_SOFTWARE
HAVE_SECONDARY_ZONE = Config.HAVE_SECONDARY_ZONE
APPLY_FIX = Config.APPLY_FIX

# Paths
WORKING_PATH = Config.WORKING_PATH
BASE_KEY_DIR = Config.BASE_KEY_DIR
X3LD_KEY_DIR = Config.X3LD_KEY_DIR
ZONE_DIR = Config.ZONE_DIR
ZONE_CONF_FILE = Config.ZONE_CONF_FILE
ZONE_DIR_SECOND_NS = Config.ZONE_DIR_SECOND_NS
ZONE_CONF_FILE_SECONDARY_NS = Config.ZONE_CONF_FILE_SECONDARY_NS
SERVER_ZONE_DIR = Config.SERVER_ZONE_DIR
SERVER_ZONE_DIR_SECOND_NS = Config.SERVER_ZONE_DIR_SECOND_NS
SERVER_ZONE_CONF_DIR_SECOND_NS = Config.SERVER_ZONE_CONF_DIR_SECOND_NS
SERVER_KEY_DIR_SECOND_NS = Config.SERVER_KEY_DIR_SECOND_NS
SERVER_ZONE_CONF_PATH_SECOND_NS = Config.SERVER_ZONE_CONF_PATH_SECOND_NS

# Analysis
CASE = Config.CASE
OUTPUT_FILE = Config.OUTPUT_FILE
INSTRUCTION_PATH = Config.INSTRUCTION_PATH
BATCH_GROK_PATH = Config.BATCH_GROK_PATH
GENERATED_GROK_PATH = Config.GENERATED_GROK_PATH
INPUT_GROK_PATH = Config.INPUT_GROK_PATH
DNSVIZ_ANALYSIS_CMD = Config.DNSVIZ_ANALYSIS_CMD
LOG_PATH = Config.LOG_PATH
NSEC3_KEY_NOT_USED_PATH = Config.NSEC3_KEY_NOT_USED_PATH
# Initialize and validate configuration on import
Config.validate()


def print_config_summary():
    """Print a summary of the current configuration."""
    info = Config.get_environment_info()
    print("=== DSECTwist Configuration ===")
    print(f"Domain: {info['domain']}")
    print(f"Primary Server: {info['primary_server']}")
    print(f"Root NS: {', '.join(info['nameservers']['root'])}")
    print(f"Working Directory: {info['paths']['working']}")
    print("==============================")


if __name__ == "__main__":
    print_config_summary()