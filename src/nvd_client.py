"""NVD API client for fetching CVE data."""

import time
import datetime
import logging
from typing import List, Dict, Any

import requests

from src.config import NVD_API_ENDPOINT


class NVDClient:
    """Client for interacting with the NIST NVD API v2.0."""

    def __init__(self):
        """Initialize the NVD client."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.session = requests.Session()
        # Rate limiting: 5 requests per 30 seconds without API key
        # Using 6-second delay to stay well within limits
        self.request_delay = 6

    def fetch_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Fetch CVEs published in the last N days.

        Args:
            days: Number of days to look back (default: 7)

        Returns:
            List of CVE objects (raw JSON from API)
        """
        # Calculate date range
        end_date = datetime.datetime.utcnow()
        start_date = end_date - datetime.timedelta(days=days)

        # Format dates in ISO8601 format with UTC timezone (Z suffix)
        # Format: YYYY-MM-DDTHH:mm:ss.sssZ
        pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000") + "Z"
        pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000") + "Z"

        self.logger.info(
            f"Fetching CVEs published between {pub_start} and {pub_end}"
        )

        results = []
        start_index = 0
        results_per_page = 2000  # Maximum to minimize requests

        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }

            try:
                response = self.session.get(
                    NVD_API_ENDPOINT,
                    params=params,
                    timeout=30
                )
            except requests.RequestException as e:
                self.logger.error(f"Network error while querying NVD API: {e}")
                break

            # Handle HTTP errors
            if response.status_code == 429:
                self.logger.warning(
                    "Rate limit exceeded. Waiting 30 seconds before retry..."
                )
                time.sleep(30)
                continue
            elif response.status_code >= 500:
                self.logger.error(
                    f"Server error {response.status_code}. Waiting 10 seconds..."
                )
                time.sleep(10)
                continue
            elif response.status_code != 200:
                self.logger.error(
                    f"NVD API returned status {response.status_code}: "
                    f"{response.text[:200]}"
                )
                break

            # Parse JSON response
            try:
                data = response.json()
            except ValueError as e:
                self.logger.error(f"Invalid JSON response: {e}")
                break

            # NVD API v2.0 returns vulnerabilities under "vulnerabilities" key
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                self.logger.debug("No vulnerabilities in response")
                break

            # Each item in vulnerabilities array is a vulnerability object
            # Return raw JSON objects as requested
            results.extend(vulnerabilities)

            # Check if there are more pages
            total_results = data.get("totalResults", 0)
            self.logger.debug(
                f"Fetched {len(vulnerabilities)} CVEs (page starting at {start_index}), "
                f"total results: {total_results}"
            )

            start_index += results_per_page

            # Check if we've fetched all results
            if start_index >= total_results:
                self.logger.debug("All CVEs fetched")
                break

            # Rate limiting: wait before next request
            if start_index < total_results:
                self.logger.debug(f"Waiting {self.request_delay} seconds before next request...")
                time.sleep(self.request_delay)

        self.logger.info(f"Fetched {len(results)} total CVEs")
        return results
