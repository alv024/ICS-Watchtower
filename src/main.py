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
from src.cisa_client import CISAClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    """Main function to start the watchtower."""
    logger.info("Watchtower started")

    days = 7

    # Test: Fetch last 7 days of CVEs from NIST NVD
    logger.info("Fetching CVEs from NIST NVD...")
    nvd_client = NVDClient()
    try:
        nvd_cves = nvd_client.fetch_recent_cves(days=days)
        nvd_count = len(nvd_cves)
        logger.info(f"NVD: Fetched {nvd_count} CVEs published in the last {days} days")
    except Exception as e:
        logger.error(f"Error fetching NVD data: {e}", exc_info=True)
        nvd_cves = []
        nvd_count = 0

    # Test: Fetch last 7 days of KEV entries from CISA
    logger.info("Fetching KEV entries from CISA...")
    cisa_client = CISAClient()
    try:
        cisa_kevs = cisa_client.get_recent_kevs(days=days)
        cisa_count = len(cisa_kevs)
        logger.info(f"CISA KEV: Fetched {cisa_count} entries added in the last {days} days")
    except Exception as e:
        logger.error(f"Error fetching CISA KEV data: {e}", exc_info=True)
        cisa_kevs = []
        cisa_count = 0

    # Compare results
    logger.info("=" * 60)
    logger.info(f"NVD CVEs: {nvd_count}")
    logger.info(f"CISA KEV entries: {cisa_count}")
    
    if nvd_count > cisa_count:
        logger.info(f"NVD returned more results ({nvd_count} vs {cisa_count})")
    elif cisa_count > nvd_count:
        logger.info(f"CISA KEV returned more results ({cisa_count} vs {nvd_count})")
    else:
        logger.info(f"Both sources returned the same number of results ({nvd_count})")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
