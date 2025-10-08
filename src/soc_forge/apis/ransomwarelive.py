"""
Ransomware.live API Client
Track ransomware groups, victims, and related IOCs
"""

from typing import Dict, Any, List, Optional
from .base import BaseAPIClient, APIResult
import logging


class RansomwareLiveClient(BaseAPIClient):
    """Client for Ransomware.live API (v2 and PRO)"""

    BASE_URL_V2 = "https://api.ransomware.live/v2"
    BASE_URL_PRO = "https://api-pro.ransomware.live"

    def __init__(self, api_key: str = ""):
        """
        Initialize Ransomware.live client

        Args:
            api_key: Optional API PRO key for enhanced features
                    If provided, uses API PRO endpoints
                    If empty, uses free v2 API with rate limits
        """
        # Use PRO API if key is provided, otherwise v2
        self.use_pro = bool(api_key and api_key != "")
        base_url = self.BASE_URL_PRO if self.use_pro else self.BASE_URL_V2

        super().__init__(
            api_key=api_key,
            base_url=base_url,
            name="ransomwarelive"
        )
        self.logger = logging.getLogger("soc_forge.apis.ransomwarelive")

        # Add API key to headers if using PRO
        if self.use_pro:
            self.session.headers.update({
                'X-Api-Key': api_key
            })
            self.logger.info("Initialized with API PRO (enhanced features enabled)")

    def check_ip(self, ip: str) -> APIResult:
        """
        Check if an IP is associated with ransomware activity
        Note: This searches across victims and cyberattacks for IP references
        """
        try:
            # Search for IP in recent victims
            victims_result = self._search_victims(ip)

            # Search for IP in cyberattacks
            attacks_result = self._search_cyberattacks(ip)

            found_in_victims = victims_result.get('victims', []) if victims_result else []
            found_in_attacks = attacks_result.get('attacks', []) if attacks_result else []

            is_found = len(found_in_victims) > 0 or len(found_in_attacks) > 0

            return APIResult(
                success=True,
                data={
                    'found': is_found,
                    'ip': ip,
                    'victims': found_in_victims,
                    'cyberattacks': found_in_attacks,
                    'total_matches': len(found_in_victims) + len(found_in_attacks),
                    'threat_level': self._calculate_threat_level(found_in_victims, found_in_attacks)
                }
            )
        except Exception as e:
            self.logger.error(f"Error checking IP {ip}: {str(e)}")
            return APIResult(
                success=False,
                data={},
                error=str(e)
            )

    def _search_victims(self, keyword: str) -> Optional[Dict[str, Any]]:
        """Search victims by keyword (IP, domain, etc.)"""
        try:
            result = self._make_request("GET", f"/searchvictims/{keyword}")
            if result.success:
                return {'victims': result.data if isinstance(result.data, list) else []}
            return None
        except Exception as e:
            self.logger.warning(f"Error searching victims: {e}")
            return None

    def _search_cyberattacks(self, keyword: str) -> Optional[Dict[str, Any]]:
        """Search cyberattacks for keyword"""
        try:
            # Get all recent cyberattacks and filter
            result = self._make_request("GET", "/recentcyberattacks")
            if result.success and isinstance(result.data, list):
                # Filter attacks that might contain the keyword
                matches = [
                    attack for attack in result.data
                    if keyword.lower() in str(attack).lower()
                ]
                return {'attacks': matches}
            return None
        except Exception as e:
            self.logger.warning(f"Error searching cyberattacks: {e}")
            return None

    def _calculate_threat_level(self, victims: List, attacks: List) -> str:
        """Calculate threat level based on findings"""
        total = len(victims) + len(attacks)

        if total >= 5:
            return "CRITICAL"
        elif total >= 3:
            return "HIGH"
        elif total >= 1:
            return "MEDIUM"
        return "CLEAN"

    def get_groups(self) -> APIResult:
        """Get list of all ransomware groups"""
        result = self._make_request("GET", "/groups")

        if result.success:
            data = result.data
            groups = []
            group_objects = []  # Keep full objects

            if isinstance(data, list):
                # List of group objects or strings
                for item in data:
                    if isinstance(item, dict):
                        # Extract group name from object - try multiple fields
                        group_name = (
                            item.get('name') or
                            item.get('group') or
                            item.get('group_name') or
                            'Unknown'
                        )
                        groups.append(group_name)
                        group_objects.append(item)  # Keep full object
                    else:
                        # Simple string
                        groups.append(str(item))
                        group_objects.append({'name': str(item)})
            elif isinstance(data, dict):
                # Dict format - could be wrapped or dict of group objects
                # Try to extract groups list
                if 'groups' in data or 'data' in data:
                    groups_list = data.get('groups', data.get('data', []))
                    if isinstance(groups_list, list):
                        for item in groups_list:
                            if isinstance(item, dict):
                                name = item.get('name', item.get('group', 'Unknown'))
                                groups.append(name)
                                group_objects.append(item)
                            else:
                                groups.append(str(item))
                                group_objects.append({'name': str(item)})
                    else:
                        groups = list(data.keys())
                        group_objects = [{'name': k, **v} if isinstance(v, dict) else {'name': k} for k, v in data.items()]
                else:
                    # It's a dict of groups where keys are group names
                    groups = list(data.keys())
                    group_objects = []
                    for k, v in data.items():
                        if isinstance(v, dict):
                            obj = {'name': k, **v}
                        else:
                            obj = {'name': k}
                        group_objects.append(obj)

            return APIResult(
                success=True,
                data={
                    'groups': groups,
                    'count': len(groups),
                    'raw_data': data,  # Original response
                    'group_objects': group_objects  # Parsed objects
                }
            )

        return result

    def get_group_info(self, group_name: str) -> APIResult:
        """Get detailed information about a specific ransomware group"""
        # PRO API uses /groups/{groupname}, v2 uses /group/{group_name}
        endpoint = f"/groups/{group_name}" if self.use_pro else f"/group/{group_name}"
        result = self._make_request("GET", endpoint)

        if result.success:
            return APIResult(
                success=True,
                data={
                    'group': group_name,
                    'info': result.data,
                    'found': True
                }
            )

        return APIResult(
            success=False,
            data={'found': False, 'group': group_name},
            error=result.error
        )

    def get_group_victims(self, group_name: str) -> APIResult:
        """Get victims claimed by a specific ransomware group"""
        result = self._make_request("GET", f"/groupvictims/{group_name}")

        if result.success:
            victims = result.data if isinstance(result.data, list) else []
            return APIResult(
                success=True,
                data={
                    'group': group_name,
                    'victims': victims,
                    'victim_count': len(victims)
                }
            )

        return result

    def get_yara_rules(self, group_name: Optional[str] = None) -> APIResult:
        """
        Get YARA rules for a specific ransomware group or all groups

        Args:
            group_name: Optional group name. If None and using PRO, gets all YARA rules
        """
        if group_name:
            result = self._make_request("GET", f"/yara/{group_name}")
        elif self.use_pro:
            # PRO API has /yara endpoint for all rules
            result = self._make_request("GET", "/yara")
        else:
            return APIResult(
                success=False,
                data={},
                error="Group name required for free API"
            )

        if result.success:
            return APIResult(
                success=True,
                data={
                    'group': group_name,
                    'yara_rules': result.data,
                    'has_rules': bool(result.data)
                }
            )

        return result

    def get_recent_victims(self) -> APIResult:
        """Get recently disclosed victims"""
        # For PRO API, try /victims/recent first, fall back to /victims/ or /recentvictims
        if self.use_pro:
            # Try recent endpoint first
            result = self._make_request("GET", "/victims/recent")
            if not result.success:
                # Fall back to /victims/ which returns all (including recent)
                self.logger.info("/victims/recent failed, trying /victims/")
                result = self._make_request("GET", "/victims/")
        else:
            result = self._make_request("GET", "/recentvictims")

        if result.success:
            data = result.data

            # Handle different response formats
            if isinstance(data, list):
                victims = data
            elif isinstance(data, dict):
                # Might be wrapped in a data field
                victims = data.get('victims', data.get('data', []))
            else:
                victims = []

            # Limit to most recent 100 if we got all victims
            if len(victims) > 100:
                victims = victims[:100]

            return APIResult(
                success=True,
                data={
                    'victims': victims,
                    'count': len(victims)
                }
            )

        return result

    def search_victims(self, keyword: str) -> APIResult:
        """Search victims by keyword"""
        # For PRO API, use /victims/search with query parameter
        if self.use_pro:
            result = self._make_request("GET", "/victims/search", params={'q': keyword})
        else:
            result = self._make_request("GET", f"/searchvictims/{keyword}")

        if result.success:
            victims = result.data if isinstance(result.data, list) else []
            return APIResult(
                success=True,
                data={
                    'keyword': keyword,
                    'victims': victims,
                    'count': len(victims)
                }
            )

        return result

    def get_sector_victims(self, sector: str, country_code: Optional[str] = None) -> APIResult:
        """Get victims by industry sector and optionally by country"""
        endpoint = f"/sectorvictims/{sector}"
        if country_code:
            endpoint = f"/sectorvictims/{sector}/{country_code}"

        result = self._make_request("GET", endpoint)

        if result.success:
            victims = result.data if isinstance(result.data, list) else []
            return APIResult(
                success=True,
                data={
                    'sector': sector,
                    'country_code': country_code,
                    'victims': victims,
                    'count': len(victims)
                }
            )

        return result

    def get_country_victims(self, country_code: str) -> APIResult:
        """Get victims by country code"""
        result = self._make_request("GET", f"/countryvictims/{country_code}")

        if result.success:
            victims = result.data if isinstance(result.data, list) else []
            return APIResult(
                success=True,
                data={
                    'country_code': country_code,
                    'victims': victims,
                    'count': len(victims)
                }
            )

        return result

    def get_cyberattacks(self, country_code: Optional[str] = None, recent_only: bool = True) -> APIResult:
        """Get cyberattacks, optionally filtered by country"""
        if country_code:
            endpoint = f"/countrycyberattacks/{country_code}"
        elif recent_only:
            endpoint = "/recentcyberattacks"
        else:
            endpoint = "/allcyberattacks"

        result = self._make_request("GET", endpoint)

        if result.success:
            attacks = result.data if isinstance(result.data, list) else []
            return APIResult(
                success=True,
                data={
                    'country_code': country_code,
                    'attacks': attacks,
                    'count': len(attacks)
                }
            )

        return result

    def check_ioc(self, ioc: str) -> APIResult:
        """
        Check if an IOC (IP, domain, hash, etc.) is associated with ransomware activity
        """
        try:
            # Search across victims
            victims_result = self.search_victims(ioc)

            # Search in cyberattacks
            attacks = []
            cyberattacks_result = self.get_cyberattacks(recent_only=False)
            if cyberattacks_result.success:
                all_attacks = cyberattacks_result.data.get('attacks', [])
                attacks = [
                    attack for attack in all_attacks
                    if ioc.lower() in str(attack).lower()
                ]

            victims = victims_result.data.get('victims', []) if victims_result.success else []

            # NEW: Search in IOC database
            ioc_matches = []
            groups_with_ioc = set()
            iocs_result = self.get_all_iocs()
            if iocs_result.success:
                all_iocs = iocs_result.data.get('iocs', [])
                for ioc_entry in all_iocs:
                    if isinstance(ioc_entry, dict):
                        # Check if IOC matches in any field
                        ioc_value = ioc_entry.get('ioc', ioc_entry.get('value', ''))
                        if ioc.lower() in str(ioc_value).lower():
                            ioc_matches.append(ioc_entry)
                            group = ioc_entry.get('group_name', ioc_entry.get('group', ''))
                            if group:
                                groups_with_ioc.add(group)

            # Extract associated groups from victims
            groups = set()
            for victim in victims:
                if isinstance(victim, dict) and 'group_name' in victim:
                    groups.add(victim['group_name'])

            for attack in attacks:
                if isinstance(attack, dict) and 'group' in attack:
                    groups.add(attack['group'])

            # Merge groups from IOC database
            groups.update(groups_with_ioc)

            is_found = len(victims) > 0 or len(attacks) > 0 or len(ioc_matches) > 0

            return APIResult(
                success=True,
                data={
                    'ioc': ioc,
                    'found': is_found,
                    'victims': victims,
                    'cyberattacks': attacks,
                    'ioc_database_matches': ioc_matches,  # NEW
                    'associated_groups': list(groups),
                    'total_matches': len(victims) + len(attacks) + len(ioc_matches),
                    'threat_level': self._calculate_threat_level(victims + ioc_matches, attacks)
                }
            )
        except Exception as e:
            self.logger.error(f"Error checking IOC {ioc}: {str(e)}")
            return APIResult(
                success=False,
                data={'ioc': ioc, 'found': False},
                error=str(e)
            )

    # ==================== API PRO EXCLUSIVE ENDPOINTS ====================

    def get_all_iocs(self) -> APIResult:
        """
        Get all IOCs (Indicators of Compromise) from ransomware groups
        Available in both free v2 and PRO APIs
        """
        # PRO API uses /iocs (plural), v2 uses /ioc (singular)
        endpoint = "/iocs" if self.use_pro else "/ioc"
        result = self._make_request("GET", endpoint)

        if result.success:
            # The API returns a list of group objects, each containing IOCs
            data = result.data
            iocs = []

            # Handle different response formats
            if isinstance(data, list):
                # List of groups with IOCs
                for group_entry in data:
                    if isinstance(group_entry, dict):
                        group_name = group_entry.get('name', group_entry.get('group', 'Unknown'))

                        # Look for IOCs in various possible fields
                        group_iocs = (
                            group_entry.get('iocs', []) or
                            group_entry.get('IOCs', []) or
                            group_entry.get('indicators', []) or
                            []
                        )

                        # Process IOCs for this group
                        for ioc_entry in group_iocs:
                            if isinstance(ioc_entry, dict):
                                # Already a dict, just add group name
                                ioc_entry['group_name'] = group_name
                                iocs.append(ioc_entry)
                            elif isinstance(ioc_entry, str):
                                # Simple string IOC
                                iocs.append({
                                    'ioc': ioc_entry,
                                    'group_name': group_name,
                                    'type': 'unknown'
                                })

            elif isinstance(data, dict):
                # Dict format - grouped by group name or IOC type
                for key, value in data.items():
                    if isinstance(value, list):
                        # Each group has a list of IOCs
                        for item in value:
                            if isinstance(item, dict):
                                if 'group' not in item and 'group_name' not in item:
                                    item['group_name'] = key
                                iocs.append(item)
                            else:
                                iocs.append({'ioc': str(item), 'group_name': key, 'type': 'unknown'})
                    elif isinstance(value, dict):
                        # Nested structure with IOC types
                        for subkey, subvalue in value.items():
                            if isinstance(subvalue, list):
                                for item in subvalue:
                                    if isinstance(item, dict):
                                        item['group_name'] = key
                                        item['type'] = subkey
                                        iocs.append(item)
                                    else:
                                        iocs.append({'ioc': str(item), 'type': subkey, 'group_name': key})

            return APIResult(
                success=True,
                data={
                    'iocs': iocs,
                    'count': len(iocs),
                    'raw_data': data  # Keep raw data for debugging
                }
            )

        return result

    def get_group_iocs(self, group_name: str) -> APIResult:
        """
        Get IOCs for a specific ransomware group
        Available in both v2 and PRO APIs

        Note: The /iocs/{group} endpoint may not be available for all groups.
        As a fallback, try fetching from the group's detailed info.
        """
        # Try the IOCs endpoint first
        result = self._make_request("GET", f"/iocs/{group_name}")

        if result.success:
            # Parse the response
            data = result.data
            iocs = []

            if isinstance(data, list):
                iocs = data
            elif isinstance(data, dict):
                # Check for IOCs in various fields
                iocs = (
                    data.get('iocs', []) or
                    data.get('IOCs', []) or
                    data.get('indicators', []) or
                    []
                )

            # Process IOCs to ensure consistent format
            formatted_iocs = []
            for ioc_entry in iocs:
                if isinstance(ioc_entry, dict):
                    formatted_iocs.append(ioc_entry)
                elif isinstance(ioc_entry, str):
                    formatted_iocs.append({
                        'ioc': ioc_entry,
                        'group_name': group_name,
                        'type': 'unknown'
                    })

            return APIResult(
                success=True,
                data={
                    'group': group_name,
                    'iocs': formatted_iocs,
                    'count': len(formatted_iocs)
                }
            )

        # If /iocs/{group} fails, try getting from group info
        self.logger.info(f"/iocs/{group_name} not available, trying group info endpoint")

        # Try to get group info which might contain IOCs
        group_info = self.get_group_info(group_name)
        if group_info.success:
            info_data = group_info.data.get('info', {})
            if isinstance(info_data, dict):
                # Extract IOCs from group info if available
                iocs_in_info = (
                    info_data.get('iocs', []) or
                    info_data.get('IOCs', []) or
                    info_data.get('indicators', []) or
                    []
                )

                if iocs_in_info:
                    return APIResult(
                        success=True,
                        data={
                            'group': group_name,
                            'iocs': iocs_in_info,
                            'count': len(iocs_in_info),
                            'source': 'group_info'
                        }
                    )

        return result

    def get_negotiations(self, group_name: Optional[str] = None, chat_id: Optional[str] = None) -> APIResult:
        """
        Get ransomware negotiation chat logs
        API PRO only

        Args:
            group_name: Optional filter by group
            chat_id: Optional specific chat ID (requires group_name)
        """
        if not self.use_pro:
            return APIResult(
                success=False,
                data={},
                error="This endpoint requires API PRO subscription"
            )

        if group_name and chat_id:
            endpoint = f"/negotiations/{group_name}/{chat_id}"
        elif group_name:
            endpoint = f"/negotiations/{group_name}"
        else:
            endpoint = "/negotiations"

        result = self._make_request("GET", endpoint)

        if result.success:
            negotiations = result.data if isinstance(result.data, list) else result.data
            return APIResult(
                success=True,
                data={
                    'group': group_name,
                    'chat_id': chat_id,
                    'negotiations': negotiations,
                    'count': len(negotiations) if isinstance(negotiations, list) else 1
                }
            )

        return result

    def get_ransom_notes(self, group_name: Optional[str] = None, note_name: Optional[str] = None) -> APIResult:
        """
        Get ransom notes from ransomware groups
        API PRO only

        Args:
            group_name: Optional filter by group
            note_name: Optional specific note (requires group_name)
        """
        if not self.use_pro:
            return APIResult(
                success=False,
                data={},
                error="This endpoint requires API PRO subscription"
            )

        if group_name and note_name:
            endpoint = f"/ransomnotes/{group_name}/{note_name}"
        elif group_name:
            endpoint = f"/ransomnotes/{group_name}"
        else:
            endpoint = "/ransomnotes"

        result = self._make_request("GET", endpoint)

        if result.success:
            notes = result.data if isinstance(result.data, list) else result.data
            return APIResult(
                success=True,
                data={
                    'group': group_name,
                    'note_name': note_name,
                    'ransom_notes': notes,
                    'count': len(notes) if isinstance(notes, list) else 1
                }
            )

        return result

    def get_statistics(self) -> APIResult:
        """
        Get ransomware activity statistics
        API PRO only
        """
        if not self.use_pro:
            return APIResult(
                success=False,
                data={},
                error="This endpoint requires API PRO subscription"
            )

        result = self._make_request("GET", "/stats")

        if result.success:
            return APIResult(
                success=True,
                data={
                    'statistics': result.data
                }
            )

        return result

    def get_press_releases(self, recent_only: bool = True) -> APIResult:
        """
        Get press releases about ransomware incidents
        API PRO only

        Args:
            recent_only: If True, get only recent press releases
        """
        if not self.use_pro:
            return APIResult(
                success=False,
                data={},
                error="This endpoint requires API PRO subscription"
            )

        endpoint = "/press/recent" if recent_only else "/press/all"
        result = self._make_request("GET", endpoint)

        if result.success:
            press = result.data if isinstance(result.data, list) else []
            return APIResult(
                success=True,
                data={
                    'press_releases': press,
                    'count': len(press)
                }
            )

        return result

    def get_8k_filings(self) -> APIResult:
        """
        Get 8-K SEC filings related to ransomware incidents
        API PRO only
        """
        if not self.use_pro:
            return APIResult(
                success=False,
                data={},
                error="This endpoint requires API PRO subscription"
            )

        result = self._make_request("GET", "/8k")

        if result.success:
            filings = result.data if isinstance(result.data, list) else []
            return APIResult(
                success=True,
                data={
                    '8k_filings': filings,
                    'count': len(filings)
                }
            )

        return result

    def get_csirt_info(self, country: str) -> APIResult:
        """
        Get CSIRT (Computer Security Incident Response Team) contact for a country
        API PRO only

        Args:
            country: Country code (e.g., 'US', 'UK', 'FR')
        """
        if not self.use_pro:
            return APIResult(
                success=False,
                data={},
                error="This endpoint requires API PRO subscription"
            )

        result = self._make_request("GET", f"/csirt/{country}")

        if result.success:
            return APIResult(
                success=True,
                data={
                    'country': country,
                    'csirt_info': result.data
                }
            )

        return result

    def list_sectors(self) -> APIResult:
        """
        Get list of all industry sectors
        API PRO only
        """
        if not self.use_pro:
            return APIResult(
                success=False,
                data={},
                error="This endpoint requires API PRO subscription"
            )

        result = self._make_request("GET", "/listsectors")

        if result.success:
            sectors = result.data if isinstance(result.data, list) else []
            return APIResult(
                success=True,
                data={
                    'sectors': sectors,
                    'count': len(sectors)
                }
            )

        return result

    def get_victim_by_id(self, victim_id: str) -> APIResult:
        """
        Get detailed victim information by ID
        API PRO only

        Args:
            victim_id: Victim identifier
        """
        if not self.use_pro:
            return APIResult(
                success=False,
                data={},
                error="This endpoint requires API PRO subscription"
            )

        result = self._make_request("GET", f"/victim/{victim_id}")

        if result.success:
            return APIResult(
                success=True,
                data={
                    'victim_id': victim_id,
                    'victim_info': result.data
                }
            )

        return result

    def validate_api_key(self) -> APIResult:
        """
        Validate API PRO key and check quota
        API PRO only
        """
        if not self.use_pro:
            return APIResult(
                success=False,
                data={},
                error="No API key configured"
            )

        result = self._make_request("GET", "/validate")

        if result.success:
            return APIResult(
                success=True,
                data={
                    'valid': True,
                    'validation_info': result.data
                }
            )

        return APIResult(
            success=False,
            data={'valid': False},
            error=result.error
        )
