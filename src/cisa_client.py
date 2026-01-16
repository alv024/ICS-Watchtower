"""CISA KEV API client for fetching Known Exploited Vulnerabilities."""

import datetime
import logging
from typing import List, Dict, Any

import requests

from src.config import CISA_KEV_FEED


class CISAClient:
    """Client for interacting with the CISA Known Exploited Vulnerabilities feed."""

    def __init__(self):
        """Initialize the CISA client."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.session = requests.Session()

    def fetch_kev_catalog(self) -> List[Dict[str, Any]]:
        """
        Fetch the full CISA KEV catalog.

        Returns:
            List of vulnerability entries (raw JSON from feed)

        Raises:
            requests.RequestException: On network or HTTP errors
            ValueError: On JSON parsing errors
        """
        self.logger.info(f"Fetching CISA KEV catalog from {CISA_KEV_FEED}")

        try:
            response = self.session.get(CISA_KEV_FEED, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            self.logger.error(f"Error fetching CISA KEV feed: {e}")
            raise

        try:
            data = response.json()
        except ValueError as e:
            self.logger.error(f"Invalid JSON response from CISA KEV feed: {e}")
            raise

        # CISA KEV feed returns data under "vulnerabilities" key
        vulnerabilities = data.get("vulnerabilities", [])
        
        self.logger.info(f"Fetched {len(vulnerabilities)} total KEV entries")
        return vulnerabilities

    def get_recent_kevs(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get KEV entries added in the last N days.

        Args:
            days: Number of days to look back (default: 7)

        Returns:
            List of recent KEV entries filtered by dateAdded field
        """
        # Fetch full catalog
        all_kevs = self.fetch_kev_catalog()

        # Calculate cutoff date
        cutoff_date = datetime.datetime.utcnow().date() - datetime.timedelta(days=days)
        
        self.logger.info(f"Filtering KEV entries added on or after {cutoff_date}")

        recent_kevs = []
        for entry in all_kevs:
            date_added_str = entry.get("dateAdded")
            if not date_added_str:
                self.logger.debug(f"Entry missing dateAdded field: {entry.get('cveID', 'unknown')}")
                continue

            try:
                # CISA KEV dateAdded is in "YYYY-MM-DD" format
                date_added = datetime.datetime.strptime(date_added_str, "%Y-%m-%d").date()
            except ValueError:
                # Try ISO format as fallback
                try:
                    date_added = datetime.datetime.fromisoformat(date_added_str.replace('Z', '+00:00')).date()
                except (ValueError, AttributeError) as e:
                    self.logger.warning(
                        f"Unrecognized date format for entry {entry.get('cveID', 'unknown')}: "
                        f"{date_added_str} - {e}"
                    )
                    continue

            if date_added >= cutoff_date:
                recent_kevs.append(entry)

        self.logger.info(f"Found {len(recent_kevs)} KEV entries added in the last {days} days")
        return recent_kevs
