"""
Threat Feed Manager
Manages external threat intelligence feeds from multiple sources
"""

import requests
from typing import Dict, List, Set, Optional, Any
from datetime import datetime, timedelta
import os
import hashlib
import ipaddress
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ThreatFeed:
    """Represents a single threat intelligence feed"""

    def __init__(
        self,
        name: str,
        url: str,
        feed_type: str = "ip",  # ip, domain, hash, url
        category: str = "general",
        refresh_hours: int = 24,
        comment_char: str = "#",
        parser: Optional[callable] = None
    ):
        self.name = name
        self.url = url
        self.feed_type = feed_type
        self.category = category
        self.refresh_hours = refresh_hours
        self.comment_char = comment_char
        self.parser = parser or self._default_parser
        self.indicators: Set[str] = set()
        self.last_updated: Optional[datetime] = None

    def _default_parser(self, line: str) -> Optional[str]:
        """Default parser for simple line-based feeds"""
        line = line.strip()

        # Skip empty lines
        if not line:
            return None

        # Skip comments
        if self.comment_char and line.startswith(self.comment_char):
            return None

        # For IP feeds, extract first IP-like pattern
        if self.feed_type == "ip":
            parts = line.split()
            for part in parts:
                # Remove port if present (e.g., 1.2.3.4:80 -> 1.2.3.4)
                ip_candidate = part.split(':')[0].split('/')[0]
                try:
                    ipaddress.ip_address(ip_candidate)
                    return ip_candidate
                except ValueError:
                    continue

        # For other types, return first non-comment field
        return line.split()[0] if line else None

    def needs_refresh(self) -> bool:
        """Check if feed needs to be refreshed"""
        if not self.last_updated:
            return True
        age = datetime.now() - self.last_updated
        return age > timedelta(hours=self.refresh_hours)


class ThreatFeedManager:
    """Manages multiple threat intelligence feeds"""

    def __init__(self, cache_dir: str = ".feed_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.feeds: Dict[str, ThreatFeed] = {}
        self._initialize_feeds()

    def _initialize_feeds(self) -> None:
        """Initialize all threat intelligence feeds"""

        # ===== ABUSE.CH FEEDS =====
        self.add_feed(ThreatFeed(
            name="abuse.ch SSL Blacklist",
            url="https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
            feed_type="ip",
            category="malware",
            refresh_hours=6
        ))

        self.add_feed(ThreatFeed(
            name="abuse.ch Feodo Tracker",
            url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            feed_type="ip",
            category="botnet",
            refresh_hours=6
        ))

        self.add_feed(ThreatFeed(
            name="abuse.ch URLhaus IPs",
            url="https://urlhaus.abuse.ch/downloads/text_online/",
            feed_type="url",
            category="malware",
            refresh_hours=12
        ))

        # ===== BLOCKLIST.DE FEEDS =====
        blocklist_de_categories = [
            ("all", "general"),
            ("ssh", "bruteforce"),
            ("mail", "spam"),
            ("apache", "web-attack"),
            ("ftp", "bruteforce"),
            ("sip", "voip-attack"),
            ("bots", "botnet"),
            ("strongips", "high-threat"),
            ("bruteforcelogin", "bruteforce")
        ]

        for category, threat_type in blocklist_de_categories:
            self.add_feed(ThreatFeed(
                name=f"blocklist.de {category}",
                url=f"https://lists.blocklist.de/lists/{category}.txt",
                feed_type="ip",
                category=threat_type,
                refresh_hours=12
            ))

        # ===== IPSUM THREAT FEEDS (Levels 1-8) =====
        for level in range(1, 9):
            self.add_feed(ThreatFeed(
                name=f"IPsum Level {level}",
                url=f"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/{level}.txt",
                feed_type="ip",
                category=f"threat-level-{level}",
                refresh_hours=24
            ))

        # ===== C2 INTEL FEEDS =====
        self.add_feed(ThreatFeed(
            name="C2IntelFeeds IPs (30d)",
            url="https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
            feed_type="ip",
            category="c2",
            refresh_hours=24,
            comment_char=None,
            parser=self._csv_parser
        ))

        self.add_feed(ThreatFeed(
            name="C2IntelFeeds Domains",
            url="https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s.csv",
            feed_type="domain",
            category="c2",
            refresh_hours=24,
            comment_char=None,
            parser=self._csv_parser
        ))

        # ===== MONTYSECURITY C2 TRACKERS =====
        montysecurity_feeds = [
            ("cobaltstrike", "Cobalt Strike C2"),
            ("metasploit", "Metasploit C2"),
            ("havoc", "Havoc C2"),
            ("brute_ratel", "Brute Ratel C2"),
            ("sliver", "Sliver C2")
        ]

        for feed_name, description in montysecurity_feeds:
            self.add_feed(ThreatFeed(
                name=f"MontySecurity {description}",
                url=f"https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/{feed_name}_ips.txt",
                feed_type="ip",
                category="c2",
                refresh_hours=12
            ))

        # ===== PHISHING & FRAUD =====
        self.add_feed(ThreatFeed(
            name="Phishing Army Blocklist",
            url="https://phishing.army/download/phishing_army_blocklist.txt",
            feed_type="domain",
            category="phishing",
            refresh_hours=24
        ))

        self.add_feed(ThreatFeed(
            name="OpenPhish Feed",
            url="https://openphish.com/feed.txt",
            feed_type="url",
            category="phishing",
            refresh_hours=6
        ))

        # ===== EMERGING THREATS =====
        self.add_feed(ThreatFeed(
            name="EmergingThreats Compromised IPs",
            url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            feed_type="ip",
            category="compromised",
            refresh_hours=12
        ))

        # ===== BOTVRIJ =====
        self.add_feed(ThreatFeed(
            name="Botvrij.eu Dst IPs",
            url="https://www.botvrij.eu/data/ioclist.ip-dst.raw",
            feed_type="ip",
            category="botnet",
            refresh_hours=24
        ))

        # ===== CINS ARMY =====
        self.add_feed(ThreatFeed(
            name="CINS Army Badguys",
            url="http://cinsscore.com/list/ci-badguys.txt",
            feed_type="ip",
            category="malicious",
            refresh_hours=24
        ))

        # ===== GREENSNOW =====
        self.add_feed(ThreatFeed(
            name="GreenSnow Blocklist",
            url="https://blocklist.greensnow.co/greensnow.txt",
            feed_type="ip",
            category="scanner",
            refresh_hours=12
        ))

        # ===== ALIENVAULT OTX =====
        self.add_feed(ThreatFeed(
            name="AlienVault Reputation",
            url="https://reputation.alienvault.com/reputation.generic",
            feed_type="ip",
            category="reputation",
            refresh_hours=24,
            comment_char=None,
            parser=self._alienvault_parser
        ))

        # ===== TALOS =====
        self.add_feed(ThreatFeed(
            name="Talos IP Blacklist",
            url="https://www.talosintelligence.com/documents/ip-blacklist",
            feed_type="ip",
            category="malicious",
            refresh_hours=24
        ))

        # ===== DSHIELD =====
        self.add_feed(ThreatFeed(
            name="DShield Top Attackers",
            url="https://isc.sans.edu/api/sources/attacks/10000/",
            feed_type="ip",
            category="attacker",
            refresh_hours=12,
            parser=self._dshield_parser
        ))

        # ===== SPAMHAUS DROP =====
        self.add_feed(ThreatFeed(
            name="Spamhaus DROP",
            url="https://www.spamhaus.org/drop/drop.txt",
            feed_type="ip",
            category="spam",
            refresh_hours=24,
            comment_char=";"
        ))

        self.add_feed(ThreatFeed(
            name="Spamhaus EDROP",
            url="https://www.spamhaus.org/drop/edrop.txt",
            feed_type="ip",
            category="spam",
            refresh_hours=24,
            comment_char=";"
        ))

        # ===== FIREHOL =====
        self.add_feed(ThreatFeed(
            name="FireHOL Level1",
            url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            feed_type="ip",
            category="high-threat",
            refresh_hours=24
        ))

        # ===== MALWARE DOMAINS =====
        self.add_feed(ThreatFeed(
            name="Malware Domain List",
            url="https://www.malwaredomainlist.com/hostslist/ip.txt",
            feed_type="ip",
            category="malware",
            refresh_hours=24
        ))

        # ===== TOR EXIT NODES =====
        self.add_feed(ThreatFeed(
            name="Tor Exit Nodes",
            url="https://check.torproject.org/exit-addresses",
            feed_type="ip",
            category="anonymizer",
            refresh_hours=6,
            parser=self._tor_parser
        ))

    def _csv_parser(self, line: str) -> Optional[str]:
        """Parser for CSV-based feeds"""
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        parts = line.split(',')
        if parts:
            indicator = parts[0].strip().strip('"')
            # Validate IP if it's an IP feed
            if indicator:
                try:
                    ipaddress.ip_address(indicator)
                    return indicator
                except ValueError:
                    return indicator if indicator else None
        return None

    def _alienvault_parser(self, line: str) -> Optional[str]:
        """Parser for AlienVault reputation feed"""
        parts = line.strip().split('#')
        if parts:
            ip_candidate = parts[0].strip()
            try:
                ipaddress.ip_address(ip_candidate)
                return ip_candidate
            except ValueError:
                pass
        return None

    def _dshield_parser(self, line: str) -> Optional[str]:
        """Parser for DShield feed"""
        # DShield API returns XML/JSON-like format
        # This is a simplified parser - may need adjustment
        line = line.strip()
        if '<ip>' in line:
            start = line.find('<ip>') + 4
            end = line.find('</ip>')
            if start > 3 and end > start:
                return line[start:end]
        return None

    def _tor_parser(self, line: str) -> Optional[str]:
        """Parser for Tor exit nodes"""
        if line.startswith('ExitAddress'):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    ipaddress.ip_address(parts[1])
                    return parts[1]
                except ValueError:
                    pass
        return None

    def add_feed(self, feed: ThreatFeed) -> None:
        """Add a threat feed to the manager"""
        self.feeds[feed.name] = feed

    def _get_cache_path(self, feed_name: str) -> Path:
        """Get cache file path for a feed"""
        # Create a safe filename from feed name
        safe_name = hashlib.md5(feed_name.encode()).hexdigest()
        return self.cache_dir / f"{safe_name}.txt"

    def _download_feed(self, feed: ThreatFeed) -> bool:
        """Download and parse a threat feed"""
        try:
            logger.info(f"Downloading feed: {feed.name}")

            # Download with timeout
            response = requests.get(
                feed.url,
                timeout=30,
                headers={'User-Agent': 'SOC-Forge-Threat-Intel/1.0'}
            )
            response.raise_for_status()

            # Parse feed
            indicators = set()
            for line in response.text.split('\n'):
                indicator = feed.parser(line)
                if indicator:
                    indicators.add(indicator.lower())

            # Update feed
            feed.indicators = indicators
            feed.last_updated = datetime.now()

            # Cache to disk
            cache_path = self._get_cache_path(feed.name)
            with open(cache_path, 'w') as f:
                f.write(f"# Last updated: {feed.last_updated}\n")
                for indicator in indicators:
                    f.write(f"{indicator}\n")

            logger.info(f"Feed {feed.name} updated: {len(indicators)} indicators")
            return True

        except Exception as e:
            logger.error(f"Error downloading feed {feed.name}: {e}")
            # Try to load from cache
            return self._load_from_cache(feed)

    def _load_from_cache(self, feed: ThreatFeed) -> bool:
        """Load feed from cache"""
        cache_path = self._get_cache_path(feed.name)
        if not cache_path.exists():
            return False

        try:
            indicators = set()
            with open(cache_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        indicators.add(line.lower())

            feed.indicators = indicators

            # Get cache file modification time
            mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
            feed.last_updated = mtime

            logger.info(f"Loaded {feed.name} from cache: {len(indicators)} indicators")
            return True

        except Exception as e:
            logger.error(f"Error loading cache for {feed.name}: {e}")
            return False

    def update_feeds(self, force: bool = False, feed_names: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Update threat feeds

        Args:
            force: Force update even if not expired
            feed_names: Only update specific feeds (None = all feeds)

        Returns:
            Dictionary of feed_name -> success status
        """
        results = {}

        feeds_to_update = self.feeds.values()
        if feed_names:
            feeds_to_update = [f for f in feeds_to_update if f.name in feed_names]

        for feed in feeds_to_update:
            # Check if update needed
            if not force and not feed.needs_refresh():
                # Try to load from cache if not already loaded
                if not feed.indicators:
                    results[feed.name] = self._load_from_cache(feed)
                else:
                    results[feed.name] = True
                continue

            # Download and update
            results[feed.name] = self._download_feed(feed)

        return results

    def check_indicator(self, indicator: str, feed_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
        """
        Check if an indicator appears in any feeds

        Args:
            indicator: The indicator to check (IP, domain, etc.)
            feed_types: Filter by feed types (None = all types)

        Returns:
            Dictionary with:
                - 'found_in': List of feed names where indicator was found
                - 'categories': List of threat categories
                - 'total_feeds_checked': Number of feeds checked
        """
        indicator = indicator.lower().strip()
        found_in = []
        categories = set()

        feeds_to_check = self.feeds.values()
        if feed_types:
            feeds_to_check = [f for f in feeds_to_check if f.feed_type in feed_types]

        for feed in feeds_to_check:
            # Ensure feed is loaded
            if not feed.indicators:
                self._load_from_cache(feed)

            # Check if indicator is in feed
            if indicator in feed.indicators:
                found_in.append(feed.name)
                categories.add(feed.category)

        return {
            'found_in': found_in,
            'categories': sorted(list(categories)),
            'total_feeds_checked': len(list(feeds_to_check)),
            'threat_level': self._calculate_threat_level(len(found_in), categories)
        }

    def _calculate_threat_level(self, hit_count: int, categories: Set[str]) -> str:
        """Calculate threat level based on hits and categories"""
        # High severity categories
        high_severity = {'c2', 'botnet', 'malware', 'high-threat', 'compromised'}

        if hit_count == 0:
            return "CLEAN"
        elif hit_count >= 10:
            return "CRITICAL"
        elif hit_count >= 5:
            return "HIGH"
        elif any(cat in high_severity for cat in categories):
            return "HIGH"
        elif hit_count >= 2:
            return "MEDIUM"
        else:
            return "LOW"

    def get_feed_stats(self) -> Dict[str, Any]:
        """Get statistics about all feeds"""
        stats = {
            'total_feeds': len(self.feeds),
            'feeds_loaded': 0,
            'total_indicators': 0,
            'by_category': {},
            'by_type': {},
            'needs_update': []
        }

        for feed in self.feeds.values():
            if feed.indicators:
                stats['feeds_loaded'] += 1
                stats['total_indicators'] += len(feed.indicators)

                # Count by category
                stats['by_category'][feed.category] = stats['by_category'].get(feed.category, 0) + 1

                # Count by type
                stats['by_type'][feed.feed_type] = stats['by_type'].get(feed.feed_type, 0) + 1

            # Check if needs update
            if feed.needs_refresh():
                stats['needs_update'].append(feed.name)

        return stats
