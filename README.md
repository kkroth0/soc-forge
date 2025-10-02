# ⚒️ SOC Forge 

SOC Forge is an IP threat intelligence platform for SOC analysts, aggregating multiple threat feeds, DNSBLs, and APIs to provide actionable IP reputation analysis and professional PDF reports.

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
- **ThreatFox** (This is getting some bugs, sorry) - abuse.ch malware IOC database with malware family attribution
- **Shodan** - Internet-connected device discovery, open port scanning, and service identification
- **IPInfo** - Geolocation, ASN information, hosting provider data, and privacy detection (VPN/proxy/Tor)

### Threat Feed Correlation
SOC Forge monitors **41+ curated threat intelligence feeds** covering:

- **Malware & Botnets:** Feodo Tracker (Botnet C2 servers) / URLhaus (Malware distribution sites) / Malware Bazaar (Malware samples and infrastructure) <br>
- **Network Abuse:** Spamhaus DROP/EDROP (Hijacked networks) / Emerging Threats Compromised IPs / DShield Top Attackers <br>
- **Phishing & Fraud:** OpenPhish feeds / PhishTank database <br>
- **APT & Targeted Attacks:** / AlienVault reputation data / ThreatFox IOC database <br>
- **Ransomware:** (in the future I think to get data from ramsomware.live) / Ransomware Tracker feeds / No More Ransom infrastructure lists

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


## ⚙️ Installation

### Prerequisites
- Python 3.8 or higher
- Internet connection for API queries
- API keys from threat intelligence providers (free tiers available)
- See `requirements.txt` for complete dependency list.

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
## Security & Privacy

- **API keys** are stored in environment variables, never in code
- **Private IP filtering** prevents analysis of internal infrastructure
- **Rate limiting** respects API provider quotas
- **Audit logging** tracks all analysis activities
- **Offline operation** supported for cached threat feeds
- **No data retention** - analysis results are not stored externally

## Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: See wiki for detailed guides
- **Community**: Built by SOC analysts for SOC analysts

---

