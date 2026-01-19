"""Configuration settings for ICS Vulnerability Watchtower."""

# NIST NVD API endpoint
NVD_API_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CISA Known Exploited Vulnerabilities JSON feed
CISA_KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ICS-related keywords to filter vulnerabilities
ICS_KEYWORDS = [
    'SCADA',
    'PLC',
    'Modbus',
    'Siemens',
    'Schneider Electric',
    'Omron',
    'Rockwell',
    'ABB',
    'Mitsubishi Electric'
]

# Check interval in hours
CHECK_INTERVAL_HOURS = 6

# Default days to look back for vulnerabilities (can be overridden in API)
DEFAULT_DAYS_LOOKBACK = 30
