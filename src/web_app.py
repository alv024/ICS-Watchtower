"""Flask web application for ICS Vulnerability Watchtower dashboard."""

import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

# Add project root to Python path and store for Flask config
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from flask import Flask, render_template, jsonify
import logging

from src.nvd_client import NVDClient
from src.cisa_client import CISAClient
from src.filters import (
    filter_ics_vulnerabilities,
    get_cve_id,
    get_cvss_score,
    get_severity_rating,
    get_nvd_published_date,
    get_nvd_description,
    get_cisa_kev_details
)
from src.config import ICS_KEYWORDS, CHECK_INTERVAL_HOURS, DEFAULT_DAYS_LOOKBACK

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Set template and static folders relative to project root
template_dir = project_root / 'templates'
static_dir = project_root / 'static'

app = Flask(
    __name__,
    template_folder=str(template_dir),
    static_folder=str(static_dir)
)
app.config['JSON_SORT_KEYS'] = False


def fetch_and_filter_data(days=7):
    """
    Fetch and filter ICS vulnerabilities from both sources.
    
    Returns:
        Tuple of (filtered_cves, nvd_cves, cisa_kevs, cisa_kev_cve_ids)
    """
    logger.info("Fetching data from NVD and CISA...")
    
    # Fetch from NVD
    nvd_client = NVDClient()
    try:
        nvd_cves = nvd_client.fetch_recent_cves(days=days)
    except Exception as e:
        logger.error(f"Error fetching NVD data: {e}", exc_info=True)
        nvd_cves = []
    
    # Fetch from CISA (recent entries)
    cisa_client = CISAClient()
    try:
        cisa_kevs = cisa_client.get_recent_kevs(days=days)
    except Exception as e:
        logger.error(f"Error fetching CISA KEV data: {e}", exc_info=True)
        cisa_kevs = []
    
    # Also fetch ALL CISA KEV catalog for cross-referencing
    # This ensures we mark NVD CVEs as CISA KEV even if they weren't added to KEV recently
    try:
        all_cisa_kevs = cisa_client.fetch_kev_catalog()
    except Exception as e:
        logger.error(f"Error fetching full CISA KEV catalog: {e}", exc_info=True)
        all_cisa_kevs = []
    
    # Combine and filter
    all_cves = nvd_cves + cisa_kevs
    ics_filtered = filter_ics_vulnerabilities(all_cves, ICS_KEYWORDS, min_severity=7.0)
    
    # Build CISA KEV CVE ID set from FULL catalog for cross-referencing
    # This way NVD CVEs will be marked as CISA KEV even if they were added to KEV long ago
    cisa_kev_cve_ids = {get_cve_id(kev) for kev in all_cisa_kevs if get_cve_id(kev)}
    
    return ics_filtered, nvd_cves, cisa_kevs, cisa_kev_cve_ids


def aggregate_statistics(ics_filtered, nvd_cves, cisa_kevs):
    """
    Aggregate statistics for charts and dashboard.
    
    Returns:
        Dictionary with statistics
    """
    stats = {
        'total_ics': len(ics_filtered),
        'total_nvd': len(nvd_cves),
        'total_cisa': len(cisa_kevs),
        'critical_count': 0,
        'severity_distribution': defaultdict(int),
        'timeline_data': defaultdict(int),
        'vendor_product_count': defaultdict(int),
        'cisa_kev_count': 0,
        'nvd_only_count': 0
    }
    
    cisa_kev_cve_ids = {get_cve_id(kev) for kev in cisa_kevs}
    
    # Process filtered vulnerabilities
    for cve in ics_filtered:
        cve_id = get_cve_id(cve)
        cvss_score = get_cvss_score(cve)
        is_cisa_kev = "cve" not in cve
        is_in_kev = cve_id in cisa_kev_cve_ids
        
        # Severity distribution
        if is_cisa_kev or is_in_kev:
            severity_rating = "CRITICAL"  # CISA KEV entries are critical
        elif cvss_score > 0:
            severity_rating = get_severity_rating(cvss_score)
        else:
            severity_rating = "Unknown"
        
        stats['severity_distribution'][severity_rating] += 1
        
        # Critical count (>= 9.0 or CISA KEV)
        if cvss_score >= 9.0 or (cvss_score == 0.0 and (is_cisa_kev or is_in_kev)):
            stats['critical_count'] += 1
        
        # Timeline data
        if "cve" in cve:
            published_date = get_nvd_published_date(cve)
            if published_date:
                stats['timeline_data'][published_date] += 1
        else:
            # CISA KEV entry
            kev_details = get_cisa_kev_details(cve)
            date_added = kev_details.get('date_added', '')
            if date_added:
                stats['timeline_data'][date_added] += 1
        
        # Vendor/Product breakdown
        if "cve" in cve:
            # For NVD, try to extract vendor/product from description/configurations
            description = get_nvd_description(cve).lower()
            for keyword in ICS_KEYWORDS:
                if keyword.lower() in description:
                    stats['vendor_product_count'][keyword] += 1
        else:
            # CISA KEV entry
            kev_details = get_cisa_kev_details(cve)
            vendor = kev_details.get('vendor_project', '')
            product = kev_details.get('product', '')
            if vendor:
                stats['vendor_product_count'][vendor] += 1
            if product:
                stats['vendor_product_count'][f"{vendor} - {product}"] += 1
        
        # CISA KEV tracking
        if is_in_kev or is_cisa_kev:
            stats['cisa_kev_count'] += 1
        else:
            stats['nvd_only_count'] += 1
    
    return stats


def format_cve_data(ics_filtered, cisa_kev_cve_ids):
    """
    Format CVE data for JSON API response.
    
    Returns:
        List of formatted CVE dictionaries
    """
    formatted = []
    
    for cve in ics_filtered:
        cve_id = get_cve_id(cve)
        is_nvd = "cve" in cve
        is_in_kev = cve_id in cisa_kev_cve_ids
        
        if is_nvd:
            # NVD CVE format
            cvss_score = get_cvss_score(cve)
            severity_rating = get_severity_rating(cvss_score)
            published_date = get_nvd_published_date(cve) or "Unknown"
            description = get_nvd_description(cve) or "No description available"
            
            formatted.append({
                'cve_id': cve_id,
                'severity_score': cvss_score if cvss_score > 0 else None,
                'severity_rating': severity_rating,
                'published_date': published_date,
                'description': description[:200],  # Truncate for display
                'full_description': description,
                'is_cisa_kev': is_in_kev,
                'source': 'NVD'
            })
        else:
            # CISA KEV format
            kev_details = get_cisa_kev_details(cve)
            
            formatted.append({
                'cve_id': kev_details['cve_id'],
                'severity_score': None,
                'severity_rating': 'CRITICAL',  # All KEV entries are critical
                'published_date': kev_details.get('date_added', 'Unknown'),
                'description': kev_details.get('vulnerability_name', ''),
                'full_description': kev_details.get('vulnerability_name', ''),
                'is_cisa_kev': True,
                'source': 'CISA KEV',
                'vendor_project': kev_details.get('vendor_project', ''),
                'product': kev_details.get('product', ''),
                'due_date': kev_details.get('due_date', ''),
                'known_ransomware_use': kev_details.get('known_ransomware_use', 'Unknown'),
                'notes': kev_details.get('notes', '')
            })
    
    return formatted


@app.route('/')
def index():
    """Main dashboard page."""
    from flask import request
    days = request.args.get('days', default=DEFAULT_DAYS_LOOKBACK, type=int)
    days = max(1, min(days, 365))  # Limit between 1 and 365 days
    return render_template('index.html', default_days=days)


@app.route('/api/data')
def api_data():
    """JSON API endpoint for CVE data."""
    from flask import request
    days = request.args.get('days', default=DEFAULT_DAYS_LOOKBACK, type=int)
    days = max(1, min(days, 365))  # Limit between 1 and 365 days
    
    ics_filtered, nvd_cves, cisa_kevs, cisa_kev_cve_ids = fetch_and_filter_data(days)
    formatted_data = format_cve_data(ics_filtered, cisa_kev_cve_ids)
    
    return jsonify({
        'success': True,
        'data': formatted_data,
        'days': days,
        'last_updated': datetime.utcnow().isoformat() + 'Z'
    })


@app.route('/api/diagnostics')
def api_diagnostics():
    """Diagnostic endpoint to check CISA KEV and NVD overlap."""
    from flask import request
    
    logger.info("Running diagnostics to check CISA KEV and NVD overlap...")
    
    # Fetch recent CISA KEV entries (from last 30 days)
    cisa_client = CISAClient()
    try:
        recent_kevs = cisa_client.get_recent_kevs(days=30)
    except Exception as e:
        logger.error(f"Error fetching CISA KEV: {e}", exc_info=True)
        recent_kevs = []
    
    # Also fetch ALL CISA KEV catalog to compare
    try:
        all_kevs = cisa_client.fetch_kev_catalog()
    except Exception as e:
        logger.error(f"Error fetching full CISA KEV catalog: {e}", exc_info=True)
        all_kevs = []
    
    # Get CVE IDs from CISA KEV
    cisa_cve_ids = {get_cve_id(kev) for kev in recent_kevs if get_cve_id(kev)}
    all_cisa_cve_ids = {get_cve_id(kev) for kev in all_kevs if get_cve_id(kev)}
    
    # Fetch NVD CVEs from last 30 days
    days = 30
    nvd_client = NVDClient()
    try:
        nvd_cves = nvd_client.fetch_recent_cves(days=days)
    except Exception as e:
        logger.error(f"Error fetching NVD data: {e}", exc_info=True)
        nvd_cves = []
    
    nvd_cve_ids = {get_cve_id(cve) for cve in nvd_cves if get_cve_id(cve)}
    
    # Find overlaps
    overlap_recent = cisa_cve_ids.intersection(nvd_cve_ids)
    overlap_all = all_cisa_cve_ids.intersection(nvd_cve_ids)
    
    # Find CISA KEV CVEs NOT in recent NVD (might be older CVEs)
    cisa_not_in_nvd_recent = cisa_cve_ids - nvd_cve_ids
    
    # Get details for overlapping CVEs
    overlap_details = []
    for cve_id in overlap_recent:
        # Find in CISA KEV
        kev_entry = next((kev for kev in recent_kevs if get_cve_id(kev) == cve_id), None)
        # Find in NVD
        nvd_entry = next((cve for cve in nvd_cves if get_cve_id(cve) == cve_id), None)
        
        if kev_entry and nvd_entry:
            kev_details = get_cisa_kev_details(kev_entry)
            nvd_published = get_nvd_published_date(nvd_entry)
            nvd_cvss = get_cvss_score(nvd_entry)
            
            overlap_details.append({
                'cve_id': cve_id,
                'cisa_date_added': kev_details.get('date_added'),
                'nvd_published': nvd_published,
                'nvd_cvss': nvd_cvss,
                'severity': get_severity_rating(nvd_cvss) if nvd_cvss > 0 else 'Unknown'
            })
    
    return jsonify({
        'success': True,
        'diagnostics': {
            'cisa_kev_recent_count': len(recent_kevs),
            'cisa_kev_total_count': len(all_kevs),
            'nvd_recent_count': len(nvd_cves),
            'cisa_cve_ids_recent': len(cisa_cve_ids),
            'cisa_cve_ids_total': len(all_cisa_cve_ids),
            'nvd_cve_ids': len(nvd_cve_ids),
            'overlap_recent_count': len(overlap_recent),
            'overlap_all_count': len(overlap_all),
            'cisa_not_in_nvd_recent': len(cisa_not_in_nvd_recent),
            'overlap_details': overlap_details,
            'cisa_cve_ids_list': sorted(list(cisa_cve_ids)),
            'cisa_not_in_nvd_list': sorted(list(cisa_not_in_nvd_recent))[:20],  # First 20
            'explanation': {
                'issue': 'CISA KEV uses dateAdded (when added to KEV), while NVD uses published date (when CVE was published).',
                'result': f'Found {len(overlap_recent)} CVEs that are both in recent CISA KEV AND published in NVD in last 30 days.',
                'note': f'{len(cisa_not_in_nvd_recent)} CISA KEV CVEs were NOT in recent NVD results (likely published earlier).'
            }
        }
    })


@app.route('/api/stats')
def api_stats():
    """JSON API endpoint for statistics."""
    from flask import request
    days = request.args.get('days', default=DEFAULT_DAYS_LOOKBACK, type=int)
    days = max(1, min(days, 365))  # Limit between 1 and 365 days
    
    ics_filtered, nvd_cves, cisa_kevs, cisa_kev_cve_ids = fetch_and_filter_data(days)
    stats = aggregate_statistics(ics_filtered, nvd_cves, cisa_kevs)
    stats['days'] = days
    
    # Convert defaultdicts to regular dicts for JSON serialization
    stats['severity_distribution'] = dict(stats['severity_distribution'])
    stats['timeline_data'] = dict(stats['timeline_data'])
    stats['vendor_product_count'] = dict(stats['vendor_product_count'])
    
    # Sort timeline data by date
    timeline_sorted = sorted(stats['timeline_data'].items())
    stats['timeline_dates'] = [item[0] for item in timeline_sorted]
    stats['timeline_counts'] = [item[1] for item in timeline_sorted]
    
    # Sort vendor/product by count (top 10)
    vendor_sorted = sorted(
        stats['vendor_product_count'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    stats['vendor_labels'] = [item[0] for item in vendor_sorted]
    stats['vendor_counts'] = [item[1] for item in vendor_sorted]
    
    stats['last_updated'] = datetime.utcnow().isoformat() + 'Z'
    
    return jsonify({
        'success': True,
        'stats': stats
    })


if __name__ == '__main__':
    logger.info("Starting ICS Vulnerability Watchtower web server...")
    logger.info("Open http://127.0.0.1:5000 in your browser")
    app.run(debug=True, host='127.0.0.1', port=5000)
