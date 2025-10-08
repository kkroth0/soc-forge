# Ransomware.live Integration

SOC Forge integrates with [ransomware.live](https://www.ransomware.live) to provide ransomware intelligence covering 291+ active groups, thousands of victim records, and real-time attack data.

## Quick Start

Access via **Menu Option 8** (Ransomware Intelligence)

**No API key required** - Free API v2 with fair use rate limits

## Features

| Option | Feature | Description |
|--------|---------|-------------|
| 1 | **IOC Analysis** | Check IPs, domains, or hashes. Returns threat level (CRITICAL/HIGH/MEDIUM/CLEAN), associated groups, and affected victims |
| 2 | **Group Listing** | Browse all 291+ ransomware groups in 3-column format |
| 3 | **Victim Search** | Search by organization name, domain, or keyword |
| 4 | **Recent Activity** | View last 15 victims and 10 cyberattacks |
| 5 | **Group Intelligence** | Detailed profiles with victim lists, YARA rules, and targeting patterns |

**Threat Levels:** CRITICAL (5+ matches), HIGH (3-4), MEDIUM (1-2), CLEAN (0)

## Usage Examples

```
# Check IP for ransomware activity
Menu 8 → Option 1 → Enter: 192.168.1.1

# Get LockBit group intelligence
Menu 8 → Option 5 → Enter: lockbit

# Track latest campaigns
Menu 8 → Option 4
```

## For SOC Analysts

- **IOC Validation** - Instantly verify ransomware associations
- **Attribution** - Identify attacking groups
- **Victim Intelligence** - Check if organizations are targeted
- **Proactive Defense** - Monitor emerging threats
- **Detection Engineering** - Access YARA rules

## Implementation

**Files:**
- [src/soc_forge/apis/ransomwarelive.py](src/soc_forge/apis/ransomwarelive.py) - API client
- [src/soc_forge/cli/interface.py](src/soc_forge/cli/interface.py) - CLI interface
- [src/soc_forge/core/analyzer.py](src/soc_forge/core/analyzer.py) - Auto-initialization

**Key Endpoints:** `/groups`, `/group/{name}`, `/groupvictims/{name}`, `/yara/{name}`, `/searchvictims/{keyword}`, `/recentvictims`, `/recentcyberattacks`

## Example Output

### IOC Found
```
⚠ IOC FOUND IN RANSOMWARE ACTIVITY ⚠

IOC: malicious-domain.com
Threat Level: HIGH
Total Matches: 3
Associated Groups: lockbit, blackcat

Victims Found (3):
Organization          Group      Date
------------------   ---------   ----------
Acme Corporation     lockbit     2024-01-15
Tech Solutions Inc   blackcat    2024-01-10
Global Industries    lockbit     2024-01-05
```

### Group Intelligence
```
================================================================================
RANSOMWARE GROUP: LOCKBIT
================================================================================

Group Profile
┌─────────────────────────────────────────┐
│ Group Name: lockbit                     │
│ Status: Active                          │
│ Profile: Ransomware-as-a-Service (RaaS)│
└─────────────────────────────────────────┘

Victims (150)
Organization                    Country         Date
----------------------------   ------------    ----------
Healthcare Corp                USA             2024-01-20
Manufacturing Ltd              Germany         2024-01-18
Financial Services Inc         UK              2024-01-15

YARA Rules Available: Yes
```

## Limitations

- Fair use rate limits (API PRO: 3000 calls/day)
- Victim disclosures may be delayed
- YARA rules not available for all groups

## Resources

- **API Docs**: https://www.ransomware.live/apidocs
- **GitHub**: https://github.com/jmousqueton/ransomware.live
