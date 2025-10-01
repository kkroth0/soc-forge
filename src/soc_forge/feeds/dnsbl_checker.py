"""
DNSBL (DNS-based Blackhole List) Checker
Query multiple DNS blacklist servers to check IP reputation
"""

import socket
import ipaddress
from typing import Dict, List, Optional, Set
import concurrent.futures
import logging

logger = logging.getLogger(__name__)


class DNSBLChecker:
    """Check IPs against multiple DNS-based blackhole lists"""

    # Comprehensive list of DNSBL servers
    DNSBL_SERVERS = [
        # ===== SPAMHAUS =====
        {
            'name': 'Spamhaus ZEN',
            'server': 'zen.spamhaus.org',
            'category': 'spam',
            'description': 'Spamhaus Block List (combined)'
        },
        {
            'name': 'Spamhaus SBL',
            'server': 'sbl.spamhaus.org',
            'category': 'spam',
            'description': 'Spamhaus Block List'
        },
        {
            'name': 'Spamhaus XBL',
            'server': 'xbl.spamhaus.org',
            'category': 'exploit',
            'description': 'Exploits Block List'
        },
        {
            'name': 'Spamhaus PBL',
            'server': 'pbl.spamhaus.org',
            'category': 'policy',
            'description': 'Policy Block List'
        },
        {
            'name': 'Spamhaus DROP',
            'server': 'dbl.spamhaus.org',
            'category': 'spam',
            'description': 'Domain Block List'
        },

        # ===== BARRACUDA =====
        {
            'name': 'Barracuda',
            'server': 'b.barracudacentral.org',
            'category': 'spam',
            'description': 'Barracuda Reputation Block List'
        },

        # ===== SPAMCOP =====
        {
            'name': 'SpamCop',
            'server': 'bl.spamcop.net',
            'category': 'spam',
            'description': 'SpamCop Blocking List'
        },

        # ===== SORBS =====
        {
            'name': 'SORBS Aggregated',
            'server': 'dnsbl.sorbs.net',
            'category': 'spam',
            'description': 'SORBS Aggregated zone'
        },
        {
            'name': 'SORBS SPAM',
            'server': 'spam.dnsbl.sorbs.net',
            'category': 'spam',
            'description': 'SORBS Spam sources'
        },
        {
            'name': 'SORBS Web',
            'server': 'web.dnsbl.sorbs.net',
            'category': 'spam',
            'description': 'SORBS Web form spam sources'
        },
        {
            'name': 'SORBS SMTP',
            'server': 'smtp.dnsbl.sorbs.net',
            'category': 'spam',
            'description': 'SORBS SMTP servers'
        },
        {
            'name': 'SORBS SOCKS',
            'server': 'socks.dnsbl.sorbs.net',
            'category': 'proxy',
            'description': 'SORBS Open SOCKS proxies'
        },
        {
            'name': 'SORBS HTTP',
            'server': 'http.dnsbl.sorbs.net',
            'category': 'proxy',
            'description': 'SORBS Open HTTP proxies'
        },
        {
            'name': 'SORBS Misc',
            'server': 'misc.dnsbl.sorbs.net',
            'category': 'spam',
            'description': 'SORBS Misc'
        },
        {
            'name': 'SORBS Zombie',
            'server': 'zombie.dnsbl.sorbs.net',
            'category': 'botnet',
            'description': 'SORBS Zombie/drone servers'
        },

        # ===== UCEPROTECT =====
        {
            'name': 'UCEPROTECT Level 1',
            'server': 'dnsbl-1.uceprotect.net',
            'category': 'spam',
            'description': 'UCEPROTECT Network Level 1'
        },
        {
            'name': 'UCEPROTECT Level 2',
            'server': 'dnsbl-2.uceprotect.net',
            'category': 'spam',
            'description': 'UCEPROTECT Network Level 2'
        },
        {
            'name': 'UCEPROTECT Level 3',
            'server': 'dnsbl-3.uceprotect.net',
            'category': 'spam',
            'description': 'UCEPROTECT Network Level 3'
        },

        # ===== PROOFPOINT =====
        {
            'name': 'Proofpoint',
            'server': 'bl.emailbasura.org',
            'category': 'spam',
            'description': 'Proofpoint Dynamic Reputation'
        },

        # ===== INVALUEMENT =====
        {
            'name': 'iVMSIP',
            'server': 'ivmSIP.dnsbl.invaluement.com',
            'category': 'spam',
            'description': 'Invaluement SIP'
        },
        {
            'name': 'iVMURI',
            'server': 'ivmURI.dnsbl.invaluement.com',
            'category': 'spam',
            'description': 'Invaluement URI'
        },

        # ===== DRONE BL =====
        {
            'name': 'DroneBL',
            'server': 'dnsbl.dronebl.org',
            'category': 'botnet',
            'description': 'DroneBL - Drones/Zombies/Bots'
        },

        # ===== ABUSE.CH =====
        {
            'name': 'abuse.ch',
            'server': 'spam.abuse.ch',
            'category': 'spam',
            'description': 'abuse.ch Spam'
        },

        # ===== MAILSPIKE =====
        {
            'name': 'Mailspike BL',
            'server': 'bl.mailspike.net',
            'category': 'spam',
            'description': 'Mailspike Blacklist'
        },
        {
            'name': 'Mailspike Reputation',
            'server': 'rep.mailspike.net',
            'category': 'reputation',
            'description': 'Mailspike Reputation'
        },

        # ===== NJABL (Now retired but some still use it) =====
        {
            'name': 'NJABL',
            'server': 'dnsbl.njabl.org',
            'category': 'spam',
            'description': 'Not Just Another Bogus List'
        },

        # ===== PSBL =====
        {
            'name': 'PSBL',
            'server': 'psbl.surriel.com',
            'category': 'spam',
            'description': 'Passive Spam Block List'
        },

        # ===== BLOCKLISTDE =====
        {
            'name': 'BlocklistDE',
            'server': 'bl.blocklist.de',
            'category': 'attack',
            'description': 'Blocklist.de Attacks'
        },

        # ===== CBL =====
        {
            'name': 'CBL',
            'server': 'cbl.abuseat.org',
            'category': 'exploit',
            'description': 'Composite Blocking List'
        },

        # ===== TRUNCATE =====
        {
            'name': 'Truncate',
            'server': 'truncate.gbudb.net',
            'category': 'spam',
            'description': 'Truncate GBUDB'
        },

        # ===== WPBL =====
        {
            'name': 'WPBL',
            'server': 'db.wpbl.info',
            'category': 'spam',
            'description': 'Weighted Private Block List'
        },

        # ===== CYMRU BOGONS =====
        {
            'name': 'Cymru Bogons',
            'server': 'bogons.cymru.com',
            'category': 'bogon',
            'description': 'Cymru Bogon List'
        },

        # ===== RATS DYNA =====
        {
            'name': 'RATS Dyna',
            'server': 'dyna.spamrats.com',
            'category': 'spam',
            'description': 'Spam Rats Dynamic IPs'
        },
        {
            'name': 'RATS NoPtr',
            'server': 'noptr.spamrats.com',
            'category': 'spam',
            'description': 'Spam Rats No PTR'
        },
        {
            'name': 'RATS Spam',
            'server': 'spam.spamrats.com',
            'category': 'spam',
            'description': 'Spam Rats Spam IPs'
        },

        # ===== S5H =====
        {
            'name': 'S5H',
            'server': 'all.s5h.net',
            'category': 'spam',
            'description': 'S5H All'
        },

        # ===== MANITU =====
        {
            'name': 'Manitu',
            'server': 'ix.dnsbl.manitu.net',
            'category': 'spam',
            'description': 'Manitu IX'
        },

        # ===== DNSWL (Whitelist - inverse logic) =====
        {
            'name': 'DNSWL (Whitelist)',
            'server': 'list.dnswl.org',
            'category': 'whitelist',
            'description': 'DNS Whitelist'
        },

        # ===== BACKSCATTERER =====
        {
            'name': 'Backscatterer',
            'server': 'ips.backscatterer.org',
            'category': 'backscatter',
            'description': 'Backscatterer IPs'
        },

        # ===== FABEL =====
        {
            'name': 'Fabel SpamHaus',
            'server': 'spamrbl.imp.ch',
            'category': 'spam',
            'description': 'Fabel SpamHaus'
        },

        # ===== SORBS DUL =====
        {
            'name': 'SORBS DUL',
            'server': 'dul.dnsbl.sorbs.net',
            'category': 'policy',
            'description': 'SORBS Dynamic User List'
        },

        # ===== NORDSPAM =====
        {
            'name': 'NordSpam',
            'server': 'bl.nordspam.com',
            'category': 'spam',
            'description': 'NordSpam Blacklist'
        },

        # ===== DNSBL.INFO =====
        {
            'name': 'DNSBL.info',
            'server': 'dnsbl.info',
            'category': 'spam',
            'description': 'DNSBL.info'
        },

        # ===== SORBS RECENT =====
        {
            'name': 'SORBS Recent',
            'server': 'recent.dnsbl.sorbs.net',
            'category': 'spam',
            'description': 'SORBS Recent Spam'
        },

        # ===== 0SPAM =====
        {
            'name': '0Spam',
            'server': '0spam.fusionzero.com',
            'category': 'spam',
            'description': '0Spam FusionZero'
        },

        # ===== LASHBACK =====
        {
            'name': 'Lashback',
            'server': 'ubl.unsubscore.com',
            'category': 'spam',
            'description': 'Lashback UBL'
        },
    ]

    def __init__(self, timeout: float = 2.0, max_workers: int = 10):
        """
        Initialize DNSBL checker

        Args:
            timeout: DNS query timeout in seconds
            max_workers: Maximum concurrent queries
        """
        self.timeout = timeout
        self.max_workers = max_workers

    def _reverse_ip(self, ip: str) -> str:
        """Reverse IP address octets for DNSBL query (e.g., 1.2.3.4 -> 4.3.2.1)"""
        return '.'.join(reversed(ip.split('.')))

    def _query_dnsbl(self, ip: str, dnsbl: Dict[str, str]) -> Optional[Dict[str, str]]:
        """
        Query a single DNSBL server

        Args:
            ip: IP address to check
            dnsbl: DNSBL server info

        Returns:
            DNSBL info if listed, None otherwise
        """
        try:
            # Reverse IP for DNSBL query
            reversed_ip = self._reverse_ip(ip)
            query = f"{reversed_ip}.{dnsbl['server']}"

            # Perform DNS lookup
            socket.setdefaulttimeout(self.timeout)
            result = socket.gethostbyname(query)

            # If we get a result, the IP is listed
            if result:
                logger.debug(f"IP {ip} listed in {dnsbl['name']}: {result}")
                return {
                    'name': dnsbl['name'],
                    'server': dnsbl['server'],
                    'category': dnsbl['category'],
                    'description': dnsbl['description'],
                    'result': result,
                    'listed': True
                }

        except socket.gaierror:
            # Not listed (NXDOMAIN)
            pass
        except socket.timeout:
            logger.warning(f"Timeout querying {dnsbl['name']} for {ip}")
        except Exception as e:
            logger.error(f"Error querying {dnsbl['name']} for {ip}: {e}")

        return None

    def check_ip(self, ip: str, dnsbl_list: Optional[List[str]] = None) -> Dict[str, any]:
        """
        Check IP against multiple DNSBL servers concurrently

        Args:
            ip: IP address to check
            dnsbl_list: List of DNSBL names to check (None = all)

        Returns:
            Dictionary with results:
                - listed_in: List of DNSBLs where IP is listed
                - categories: Set of threat categories
                - total_checked: Number of DNSBLs checked
                - threat_level: Overall threat level
                - is_whitelisted: True if found in whitelist
        """
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {
                'error': 'Invalid IP address',
                'listed_in': [],
                'categories': [],
                'total_checked': 0,
                'threat_level': 'UNKNOWN',
                'is_whitelisted': False
            }

        # Filter DNSBLs if specific list provided
        dnsbls_to_check = self.DNSBL_SERVERS
        if dnsbl_list:
            dnsbls_to_check = [d for d in self.DNSBL_SERVERS if d['name'] in dnsbl_list]

        # Check DNSBLs concurrently
        listed_in = []
        categories = set()
        is_whitelisted = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all queries
            future_to_dnsbl = {
                executor.submit(self._query_dnsbl, ip, dnsbl): dnsbl
                for dnsbl in dnsbls_to_check
            }

            # Collect results
            for future in concurrent.futures.as_completed(future_to_dnsbl):
                result = future.result()
                if result:
                    listed_in.append(result)
                    categories.add(result['category'])

                    # Check if whitelisted
                    if result['category'] == 'whitelist':
                        is_whitelisted = True

        # Separate blacklist and whitelist counts
        blacklist_entries = [entry for entry in listed_in if entry['category'] != 'whitelist']
        blacklist_count = len(blacklist_entries)

        # Calculate threat level based on blacklist entries only
        threat_level = self._calculate_threat_level(blacklist_count, categories, is_whitelisted)

        return {
            'listed_in': listed_in,
            'categories': sorted(list(categories)),
            'total_checked': len(dnsbls_to_check),
            'total_listings': len(listed_in),
            'blacklist_count': blacklist_count,
            'threat_level': threat_level,
            'is_whitelisted': is_whitelisted
        }

    def _calculate_threat_level(self, blacklist_count: int, categories: Set[str], is_whitelisted: bool) -> str:
        """
        Calculate threat level based on DNSBL blacklist listings

        Args:
            blacklist_count: Number of blacklist entries (excludes whitelists)
            categories: All categories including whitelist
            is_whitelisted: Whether IP is in any whitelist
        """
        # Filter out whitelist category for threat calculation
        blacklist_categories = {cat for cat in categories if cat != 'whitelist'}

        # If no blacklist entries, it's clean or trusted
        if blacklist_count == 0:
            if is_whitelisted:
                return "TRUSTED"
            return "CLEAN"

        # High severity categories
        high_severity = {'exploit', 'botnet', 'attack'}

        # Calculate threat level based on blacklist entries
        if blacklist_count >= 15:
            return "CRITICAL"
        elif blacklist_count >= 10:
            return "HIGH"
        elif blacklist_count >= 5:
            return "MEDIUM"
        elif any(cat in high_severity for cat in blacklist_categories):
            return "MEDIUM"
        else:
            return "LOW"

    def get_dnsbl_list(self) -> List[Dict[str, str]]:
        """Get list of all available DNSBL servers"""
        return self.DNSBL_SERVERS

    def get_dnsbl_by_category(self, category: str) -> List[Dict[str, str]]:
        """Get DNSBLs filtered by category"""
        return [d for d in self.DNSBL_SERVERS if d['category'] == category]
