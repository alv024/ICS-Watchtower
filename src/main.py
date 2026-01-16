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
from src.filters import filter_ics_vulnerabilities
from src.config import ICS_KEYWORDS

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

    # Apply ICS filter to both sources
    logger.info("")
    logger.info("Applying ICS keyword filter...")
    
    all_cves = nvd_cves + cisa_kevs
    ics_filtered = filter_ics_vulnerabilities(all_cves, ICS_KEYWORDS, min_severity=7.0)
    
    # Count critical (CVSS >= 9.0) vulnerabilities
    from src.filters import get_cve_id, get_cvss_score
    
    critical_count = 0
    cve_ids = []
    for cve in ics_filtered:
        cve_id = get_cve_id(cve)
        cvss_score = get_cvss_score(cve)
        
        # Count as critical if CVSS >= 9.0 or if it's from CISA KEV (known exploited)
        is_cisa_kev = "cve" not in cve
        if cvss_score >= 9.0 or (cvss_score == 0.0 and is_cisa_kev):
            # CISA KEV entries are inherently critical (known exploited)
            critical_count += 1
        
        if cve_id:
            cve_ids.append(cve_id)
    
    logger.info(f"Found {len(ics_filtered)} ICS-related vulnerabilities ({critical_count} critical)")
    logger.info("")
    
    if not ics_filtered:
        logger.info("✅ Good news! No new ICS-related vulnerabilities found in the last 7 days.")
    else:
        # Build set of CISA KEV CVE IDs for cross-referencing
        cisa_kev_cve_ids = {get_cve_id(kev) for kev in cisa_kevs}
        
        logger.info("CVE IDs of filtered results:")
        for cve_id in cve_ids:
            logger.info(f"  - {cve_id}")
        
        logger.info("")
        logger.info(f"Found {len(ics_filtered)} ICS-related vulnerabilities:")
        logger.info("")
        
        # Separate NVD CVEs and CISA KEV entries for detailed display
        nvd_ics_cves = [cve for cve in ics_filtered if "cve" in cve]
        cisa_ics_kevs = [cve for cve in ics_filtered if "cve" not in cve]
        
        from src.filters import (
            get_severity_rating,
            get_nvd_published_date,
            get_nvd_description,
            get_cisa_kev_details
        )
        
        # Display NVD CVEs with details
        for cve in nvd_ics_cves:
            cve_id = get_cve_id(cve)
            cvss_score = get_cvss_score(cve)
            severity_rating = get_severity_rating(cvss_score)
            published_date = get_nvd_published_date(cve) or "Unknown"
            description = get_nvd_description(cve) or "No description available"
            
            # Truncate description to 150 characters
            description_short = description[:150] + "..." if len(description) > 150 else description
            
            # Check if in CISA KEV
            is_in_kev = cve_id in cisa_kev_cve_ids
            kev_status = "⚠️  YES - Actively exploited!" if is_in_kev else "No"
            
            # Format severity display
            if cvss_score > 0:
                severity_str = f"{cvss_score:.1f} ({severity_rating})"
            else:
                severity_str = "Unknown"
            
            logger.info(f"{cve_id} | Severity: {severity_str} | Published: {published_date}")
            logger.info(f"Description: {description_short}")
            logger.info(f"CISA KEV: {kev_status}")
            logger.info("")
        
        # Display CISA KEV entries with details
        if cisa_ics_kevs:
            logger.info("-" * 60)
            logger.info("CISA Known Exploited Vulnerabilities (KEV) Details:")
            logger.info("-" * 60)
            logger.info("")
            
            for kev in cisa_ics_kevs:
                kev_details = get_cisa_kev_details(kev)
                
                logger.info(f"CVE ID: {kev_details['cve_id']}")
                logger.info(f"Vendor/Project: {kev_details['vendor_project']}")
                logger.info(f"Product: {kev_details['product']}")
                logger.info(f"Vulnerability Name: {kev_details['vulnerability_name']}")
                logger.info(f"Date Added to KEV: {kev_details['date_added']}")
                logger.info(f"Due Date: {kev_details['due_date']}")
                logger.info(f"Known Ransomware Use: {kev_details['known_ransomware_use']}")
                if kev_details.get('notes'):
                    logger.info(f"Notes: {kev_details['notes']}")
                logger.info("")


if __name__ == "__main__":
    main()
