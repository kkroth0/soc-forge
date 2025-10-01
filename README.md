# SOC Forge v3.0

**SOC Forge** is an advanced IP threat intelligence platform designed for Security Operations Center (SOC) analysts and security professionals. It aggregates threat data from multiple sources including commercial APIs, open-source threat feeds, and DNS blacklists to provide comprehensive IP reputation analysis and actionable intelligence.

## Overview

SOC Forge helps security teams quickly assess IP addresses by:
- Querying multiple threat intelligence APIs in parallel
- Correlating findings across 41+ curated threat intelligence feeds
- Checking reputation against 46+ DNS blacklist (DNSBL) servers
- Calculating weighted threat scores based on multi-source intelligence
- Generating professional PDF reports in multiple languages (English, Portuguese, French)
- Providing SIEM/Kibana query generation for security analytics

## Features

### Multi-Source API Integration

SOC Forge integrates with 7 major threat intelligence APIs:

- **VirusTotal** - Malware scanning with 90+ antivirus engines, URL analysis, and community reputation scoring
- **AbuseIPDB** - Community-driven IP abuse reporting with confidence scores and historical attack data
- **GreyNoise** - Internet-wide scanning activity classification (benign vs malicious noise)
- **AlienVault OTX** - Open Threat Exchange with community threat pulses and IOC correlation
- **ThreatFox** - abuse.ch malware IOC database with malware family attribution
- **Shodan** - Internet-connected device discovery, open port scanning, and service identification
- **IPInfo** - Geolocation, ASN information, hosting provider data, and privacy detection (VPN/proxy/Tor)

### Threat Feed Correlation

SOC Forge monitors **41+ curated threat intelligence feeds** covering:

**Malware & Botnets:**
- Feodo Tracker (Botnet C2 servers)
- URLhaus (Malware distribution sites)
- Malware Bazaar (Malware samples and infrastructure)

**Network Abuse:**
- Spamhaus DROP/EDROP (Hijacked networks)
- Emerging Threats Compromised IPs
- DShield Top Attackers

**Phishing & Fraud:**
- OpenPhish feeds
- PhishTank database

**APT & Targeted Attacks:**
- AlienVault reputation data
- ThreatFox IOC database

**Ransomware:**
- Ransomware Tracker feeds
- No More Ransom infrastructure lists

All feeds are automatically updated and checked during IP analysis to identify matches in real-time.

### DNS Blacklist (DNSBL) Checking

SOC Forge queries **46+ DNS blacklist servers** including:

**Spam & Email Reputation:**
- Spamhaus (ZEN, SBL, XBL, PBL)
- Barracuda Reputation Block List
- SORBS (various categories)
- SpamCop Blocking List
- PSBL (Passive Spam Block List)

**Malware & Exploit:**
- abuse.ch servers
- Malware domains blocklist

**Brute Force & Attacks:**
- BruteForceBlocker
- DShield blocklist

**Tor & Proxy:**
- TornevAll Tor exit nodes
- DroneBL proxy detection

**Multi-Category:**
- UCEPROTECT (Levels 1, 2, 3)
- Invaluement lists

Each DNSBL is queried with timeout handling and the results include both blacklist and whitelist status.

### Threat Scoring & Analysis

SOC Forge uses a weighted scoring algorithm (0-100) that considers:
- VirusTotal malicious detections (20% weight)
- AbuseIPDB confidence score (20% weight)
- Threat feed matches (25% weight)
- DNS blacklist presence (20% weight)
- Additional intelligence sources (15% weight)

Threat levels: **CRITICAL** (70-100), **HIGH** (50-69), **MEDIUM** (30-49), **LOW** (10-29), **MINIMAL** (0-9)

### Professional PDF Reports

Generate enterprise-grade threat intelligence reports with:
- **Multi-language support** - English, Portuguese (Brazil), French
- **Executive summary** - High-level risk assessment and key findings
- **Technical analysis** - Detailed source-by-source breakdown
- **DNSBL correlation** - Complete blacklist/whitelist status
- **Threat feed matches** - All feeds where IP was found
- **Network infrastructure** - ASN, hosting provider, geolocation
- **Recommendations** - Risk-based action items
- **Methodology** - Transparent scoring and analysis methods
- **References** - All data sources cited

### SIEM Integration

Generate ready-to-use queries for:
- **KQL (Kibana Query Language)** - Azure Sentinel, Elastic
- **Lucene** - Elasticsearch, Kibana
- **EQL (Event Query Language)** - Elastic Security
- **Splunk SPL** - Splunk Enterprise

Query types support source IP, destination IP, and bidirectional traffic analysis.

## Installation

### Prerequisites
- Python 3.8 or higher
- Internet connection for API queries
- API keys from threat intelligence providers (free tiers available)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/soc-forge.git
cd soc-forge
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure API keys:
```bash
cp .env.example .env
```

Edit `.env` with your API keys:
```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
IPINFO_API_KEY=your_key_here
OTX_API_KEY=your_key_here
GREYNOISE_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
THREATFOX_API_KEY=your_key_here
```

### Getting API Keys

- **VirusTotal**: https://www.virustotal.com/gui/join-us (Free: 500 requests/day)
- **AbuseIPDB**: https://www.abuseipdb.com/register (Free: 1000 requests/day)
- **IPInfo**: https://ipinfo.io/signup (Free: 50,000 requests/month)
- **AlienVault OTX**: https://otx.alienvault.com (Free with registration)
- **GreyNoise**: https://www.greynoise.io/viz/signup (Free tier available)
- **Shodan**: https://account.shodan.io/register (Free tier available)
- **ThreatFox**: https://threatfox.abuse.ch/api/ (Free API, no key required)

## Usage

### Launch Application
```bash
python soc_forge.py
```

### Main Menu Options

**[1] Threat Scan**
- Perform comprehensive IP analysis across all sources
- Real-time progress tracking
- Interactive dashboard with color-coded results
- Supports bulk analysis (multiple IPs)

**[2] Generate SIEM / Kibana Queries**
- Convert IPs to ready-to-use security queries
- KQL, Lucene, EQL, and Splunk SPL formats
- Source/Destination/Bidirectional patterns

**[3] API Configuration & Health Check**
- Verify API keys are valid
- Check rate limits and quota
- Test connectivity to all sources

**[4] Check Threat Feeds Status**
- View all 41 threat intelligence feeds
- See feed categories and descriptions
- Check last update times
- Manually update feeds

**[5] Check DNS Blacklists (DNSBL)**
- Standalone DNSBL checker
- Query all 46 blacklist servers
- Separate blacklist and whitelist results
- Detailed categorization

**[6] List Available DNSBL Servers**
- Display all configured DNSBL servers
- Show server descriptions and categories
- View server status

**[7] Generate PDF Report**
- Select language (English/Portuguese/French)
- Comprehensive threat intelligence report
- Professional formatting with charts and tables
- Includes all analysis data

### Input Formats

SOC Forge automatically extracts IPs from various formats:
```
8.8.8.8
1.1.1.1, 8.8.8.8, 208.67.222.222
192.168.1.1:8080
IP: 10.0.0.1 (from logs)
Suspicious connection from 203.0.113.45 detected
```

## Project Structure

```
soc-forge/
├── soc_forge.py                    # Main application entry point
├── src/soc_forge/
│   ├── apis/                       # API client implementations
│   │   ├── virustotal.py
│   │   ├── abuseipdb.py
│   │   ├── greynoise.py
│   │   ├── ipinfo.py
│   │   ├── otx.py
│   │   ├── shodan.py
│   │   └── threatfox.py
│   ├── cli/                        # Command-line interface
│   │   ├── interface.py            # Main menu and interactions
│   │   └── dashboard.py            # Results dashboard
│   ├── core/                       # Core analysis engine
│   │   ├── analyzer.py             # Multi-source orchestration
│   │   └── ip_parser.py            # IP extraction and validation
│   ├── feeds/                      # Threat feeds and DNSBL
│   │   ├── threat_feed_manager.py  # Feed download and correlation
│   │   ├── feed_sources.py         # 41+ feed definitions
│   │   └── dnsbl_checker.py        # 46+ DNSBL queries
│   ├── reports/                    # Report generation
│   │   ├── professional_report.py  # PDF report generator
│   │   ├── translations.py         # Multi-language support
│   │   └── report_sections.py      # Report components
│   ├── utils/                      # Utilities
│   │   ├── threat_scoring.py       # Weighted threat scoring
│   │   └── kql_generator.py        # SIEM query generation
│   └── queries/                    # Query templates
├── outputs/
│   ├── reports/                    # Generated PDF reports
│   ├── logs/                       # Application logs
│   └── feeds/                      # Cached threat feeds
└── .env                            # API key configuration
```

## Threat Scoring Methodology

SOC Forge calculates threat scores using a weighted algorithm:

1. **VirusTotal Analysis (20%)**
   - Malicious detections / Total engines ratio
   - Reputation score
   - Community votes

2. **AbuseIPDB Assessment (20%)**
   - Abuse confidence percentage
   - Number of reports
   - Report recency

3. **Threat Feed Correlation (25%)**
   - Number of feed matches
   - Feed category severity
   - Feed reliability weighting

4. **DNS Blacklist Status (20%)**
   - Number of blacklist entries
   - Blacklist category (spam vs malware)
   - Whitelist presence consideration

5. **Additional Intelligence (15%)**
   - GreyNoise classification
   - Shodan exposure analysis
   - Network infrastructure reputation

Final scores range from 0-100 and map to threat levels for actionable decision-making.

## Security & Privacy

- **API keys** are stored in environment variables, never in code
- **Private IP filtering** prevents analysis of internal infrastructure
- **Rate limiting** respects API provider quotas
- **Audit logging** tracks all analysis activities
- **Offline operation** supported for cached threat feeds
- **No data retention** - analysis results are not stored externally

## Requirements

```
Python 3.8+
requests
python-dotenv
rich (CLI interface)
reportlab (PDF generation)
dnspython (DNSBL queries)
```

See `requirements.txt` for complete dependency list.

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Acknowledgments

**Threat Intelligence Providers:**
- VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX, abuse.ch (ThreatFox, Feodo, URLhaus), Shodan, IPInfo

**Threat Feed Sources:**
- Spamhaus, Emerging Threats, DShield, OpenPhish, PhishTank, Ransomware Tracker, and many more

**DNSBL Operators:**
- Spamhaus, Barracuda, SORBS, SpamCop, UCEPROTECT, and community-operated lists

**Open Source:**
- Rich (CLI framework), ReportLab (PDF generation), dnspython (DNS queries)

## Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: See wiki for detailed guides
- **Community**: Built by SOC analysts for SOC analysts

---

**SOC Forge v3.0** - Advanced IP Threat Intelligence Platform
