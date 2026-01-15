"""Main entry point for ICS Vulnerability Watchtower."""

import sys
import os
from pathlib import Path

# Add project root to Python path to allow running as script
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import logging

from src.nvd_client import NVDClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    """Main function to start the watchtower."""
    logger.info("Watchtower started")

    # Test: Fetch last 7 days of CVEs
    client = NVDClient()
    cves = client.fetch_recent_cves(days=7)
    logger.info(f"Fetched {len(cves)} CVEs published in the last 7 days")


if __name__ == "__main__":
    main()
