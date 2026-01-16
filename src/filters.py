"""Filters for ICS-related vulnerabilities."""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def _extract_nvd_description(cve_obj: Dict[str, Any]) -> str:
    """
    Extract description from NVD CVE object.

    Args:
        cve_obj: CVE object from NVD API v2.0

    Returns:
        Description text or empty string
    """
    try:
        cve = cve_obj.get("cve", {})
        descriptions = cve.get("descriptions", [])
        
        # Try to find English description first
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        
        # If no English description, use first available
        if descriptions:
            return descriptions[0].get("value", "")
    except (KeyError, IndexError, AttributeError) as e:
        logger.debug(f"Error extracting description: {e}")
    
    return ""


def _extract_nvd_vendors_products(cve_obj: Dict[str, Any]) -> List[str]:
    """
    Extract vendor and product names from NVD CVE configurations.

    Args:
        cve_obj: CVE object from NVD API v2.0

    Returns:
        List of vendor and product names
    """
    vendors_products = []
    
    try:
        cve = cve_obj.get("cve", {})
        configurations = cve.get("configurations", [])
        
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                # Extract from cpeMatch (CPE strings contain vendor/product info)
                cpe_match = node.get("cpeMatch", [])
                for match in cpe_match:
                    criteria = match.get("criteria", "")
                    # CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3] if len(parts) > 3 else ""
                        product = parts[4] if len(parts) > 4 else ""
                        if vendor and vendor != "*":
                            vendors_products.append(vendor)
                        if product and product != "*":
                            vendors_products.append(product)
                
                # Also check children nodes recursively
                children = node.get("children", [])
                for child in children:
                    child_cpe_match = child.get("cpeMatch", [])
                    for match in child_cpe_match:
                        criteria = match.get("criteria", "")
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3] if len(parts) > 3 else ""
                            product = parts[4] if len(parts) > 4 else ""
                            if vendor and vendor != "*":
                                vendors_products.append(vendor)
                            if product and product != "*":
                                vendors_products.append(product)
    except (KeyError, IndexError, AttributeError) as e:
        logger.debug(f"Error extracting vendors/products: {e}")
    
    return vendors_products


def _get_nvd_cvss_score(cve_obj: Dict[str, Any]) -> float:
    """
    Get CVSS base score from NVD CVE object.

    Args:
        cve_obj: CVE object from NVD API v2.0

    Returns:
        CVSS base score or 0.0 if not found
    """
    try:
        cve = cve_obj.get("cve", {})
        metrics = cve.get("metrics", {})
        
        # Try CVSS v3.1 first
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            base_score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0.0)
            if base_score:
                return float(base_score)
        
        # Try CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            base_score = cvss_v30[0].get("cvssData", {}).get("baseScore", 0.0)
            if base_score:
                return float(base_score)
        
        # Try CVSS v2 as fallback
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            base_score = cvss_v2[0].get("cvssData", {}).get("baseScore", 0.0)
            if base_score:
                return float(base_score)
    except (KeyError, IndexError, ValueError, AttributeError) as e:
        logger.debug(f"Error extracting CVSS score: {e}")
    
    return 0.0


def get_cve_id(cve_obj: Dict[str, Any]) -> str:
    """
    Get CVE ID from CVE object (NVD or CISA format).

    Args:
        cve_obj: CVE object from NVD API v2.0 or CISA KEV feed

    Returns:
        CVE ID or empty string
    """
    # Check if it's NVD format (has 'cve' key)
    if "cve" in cve_obj:
        try:
            cve = cve_obj.get("cve", {})
            return cve.get("id", "")
        except (KeyError, AttributeError):
            return ""
    else:
        # CISA KEV format
        return cve_obj.get("cveID", "")


def get_cvss_score(cve_obj: Dict[str, Any]) -> float:
    """
    Get CVSS base score from CVE object (NVD format).

    Args:
        cve_obj: CVE object from NVD API v2.0

    Returns:
        CVSS base score or 0.0 if not found or not NVD format
    """
    if "cve" not in cve_obj:
        # CISA KEV entries don't have CVSS scores
        return 0.0
    
    return _get_nvd_cvss_score(cve_obj)


def get_severity_rating(cvss_score: float) -> str:
    """
    Get severity rating string from CVSS score.

    Args:
        cvss_score: CVSS base score

    Returns:
        Severity rating: CRITICAL, HIGH, MEDIUM, LOW, or Unknown
    """
    if cvss_score == 0.0:
        return "Unknown"
    elif cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score >= 0.1:
        return "LOW"
    else:
        return "Unknown"


def get_nvd_published_date(cve_obj: Dict[str, Any]) -> str:
    """
    Get published date from NVD CVE object.

    Args:
        cve_obj: CVE object from NVD API v2.0

    Returns:
        Published date in YYYY-MM-DD format or empty string
    """
    try:
        cve = cve_obj.get("cve", {})
        published = cve.get("published", "")
        if published:
            # Format: 2025-01-15T12:34:56.789Z
            date_part = published.split("T")[0]
            return date_part
    except (KeyError, AttributeError, IndexError) as e:
        logger.debug(f"Error extracting published date: {e}")
    
    return ""


def get_nvd_description(cve_obj: Dict[str, Any]) -> str:
    """
    Get description from NVD CVE object (public wrapper).

    Args:
        cve_obj: CVE object from NVD API v2.0

    Returns:
        Description text or empty string
    """
    return _extract_nvd_description(cve_obj)


def get_cisa_kev_details(kev_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract details from CISA KEV entry.

    Args:
        kev_obj: KEV entry from CISA feed

    Returns:
        Dictionary with KEV details
    """
    return {
        "cve_id": kev_obj.get("cveID", ""),
        "vendor_project": kev_obj.get("vendorProject", ""),
        "product": kev_obj.get("product", ""),
        "vulnerability_name": kev_obj.get("vulnerabilityName", ""),
        "date_added": kev_obj.get("dateAdded", ""),
        "due_date": kev_obj.get("dueDate", ""),
        "known_ransomware_use": kev_obj.get("knownRansomwareCampaignUse", "Unknown"),
        "notes": kev_obj.get("notes", "")
    }


# Keep private versions for internal use
def _get_nvd_cve_id(cve_obj: Dict[str, Any]) -> str:
    """Get CVE ID from NVD CVE object (internal)."""
    return get_cve_id(cve_obj)


def _get_cisa_cve_id(kev_obj: Dict[str, Any]) -> str:
    """Get CVE ID from CISA KEV object (internal)."""
    return get_cve_id(kev_obj)


def _matches_keywords(text: str, keywords: List[str]) -> bool:
    """
    Check if any keyword appears in text (case-insensitive).

    Args:
        text: Text to search
        keywords: List of keywords to search for

    Returns:
        True if any keyword is found
    """
    text_lower = text.lower()
    for keyword in keywords:
        if keyword.lower() in text_lower:
            return True
    return False


def filter_ics_vulnerabilities(
    cve_list: List[Dict[str, Any]],
    keywords: List[str],
    min_severity: float = 7.0
) -> List[Dict[str, Any]]:
    """
    Filter CVEs to only include ICS-related vulnerabilities with severity >= min_severity.

    Args:
        cve_list: List of CVE objects (can be from NVD or CISA)
        keywords: List of ICS-related keywords to search for
        min_severity: Minimum CVSS score (default: 7.0 for HIGH/CRITICAL)

    Returns:
        Filtered list of ICS-related CVEs with severity >= min_severity
    """
    filtered = []
    
    for cve_obj in cve_list:
        # Determine if this is a NVD CVE (has 'cve' key) or CISA KEV entry
        is_nvd = "cve" in cve_obj
        
        # Extract relevant fields based on source
        if is_nvd:
            # NVD CVE structure
            description = _extract_nvd_description(cve_obj)
            vendors_products = _extract_nvd_vendors_products(cve_obj)
            cvss_score = _get_nvd_cvss_score(cve_obj)
            cve_id = _get_nvd_cve_id(cve_obj)
            
            # Combine all searchable text
            searchable_text = f"{description} {' '.join(vendors_products)}"
        else:
            # CISA KEV structure (simpler)
            description = cve_obj.get("vulnerabilityName", "") or cve_obj.get("description", "")
            vendor = cve_obj.get("vendorProject", "")
            product = cve_obj.get("product", "")
            searchable_text = f"{description} {vendor} {product}"
            cve_id = _get_cisa_cve_id(cve_obj)
            # CISA KEV entries don't have CVSS scores in the feed
            # So we'll accept all that match keywords (severity check skipped)
            cvss_score = 10.0  # Assume high severity for KEV entries
        
        # Check keyword match
        if not _matches_keywords(searchable_text, keywords):
            continue
        
        # Check severity (only for NVD CVEs, or skip for CISA KEV)
        if is_nvd and cvss_score < min_severity:
            continue
        
        # Passed all filters
        filtered.append(cve_obj)
        logger.debug(f"Matched ICS CVE: {cve_id} (CVSS: {cvss_score:.1f})")
    
    return filtered
