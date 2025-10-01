"""
Report Section Helpers
Helper methods for generating report sections
"""

from typing import List, Dict, Any
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

styles = getSampleStyleSheet()


def add_virustotal_section(story: List, vt_data: Dict[str, Any]):
    """Add VirusTotal section to report"""
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch

    heading_style = styles['Heading3']
    story.append(Paragraph("VirusTotal Analysis", heading_style))
    story.append(Spacer(1, 10))

    # Summary
    malicious = vt_data.get('malicious', 0)
    suspicious = vt_data.get('suspicious', 0)
    total = vt_data.get('total_engines', 0)

    summary_text = f"""
    <b>Detection Summary:</b><br/>
    • Malicious: {malicious}<br/>
    • Suspicious: {suspicious}<br/>
    • Harmless: {vt_data.get('harmless', 0)}<br/>
    • Undetected: {vt_data.get('undetected', 0)}<br/>
    • Total Engines: {total}<br/>
    • Reputation Score: {vt_data.get('reputation', 'N/A')}
    """
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 10))

    # Top detecting engines
    engines_detected = vt_data.get('engines_detected', [])
    if engines_detected:
        story.append(Paragraph("<b>Detections by Security Vendors:</b>", styles['Normal']))
        engine_data = [["Vendor", "Result", "Category"]]

        for engine in engines_detected[:10]:  # Top 10
            engine_data.append([
                str(engine.get('engine', 'Unknown')),
                str(engine.get('result', 'N/A')),
                str(engine.get('category', 'N/A'))
            ])

        engine_table = Table(engine_data, colWidths=[2*inch, 2*inch, 1.5*inch])
        engine_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        story.append(engine_table)


def add_abuseipdb_section(story: List, abuse_data: Dict[str, Any]):
    """Add AbuseIPDB section to report"""
    heading_style = styles['Heading3']
    story.append(Paragraph("AbuseIPDB Analysis", heading_style))
    story.append(Spacer(1, 10))

    conf_score = abuse_data.get('confidence_score', 0)
    total_reports = abuse_data.get('total_reports', 0)

    summary_text = f"""
    <b>Abuse Confidence:</b> {conf_score}%<br/>
    <b>Total Reports:</b> {total_reports}<br/>
    <b>Country:</b> {str(abuse_data.get('country_name', 'N/A'))} ({str(abuse_data.get('country_code', 'N/A'))})<br/>
    <b>ISP:</b> {str(abuse_data.get('isp', 'N/A'))}<br/>
    <b>Usage Type:</b> {str(abuse_data.get('usage_type', 'N/A'))}<br/>
    <b>Domain:</b> {str(abuse_data.get('domain', 'N/A'))}
    """
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 10))

    # Categories
    categories = abuse_data.get('categories', [])
    if categories:
        categories_str = ', '.join([str(c) for c in categories])
        story.append(Paragraph(f"<b>Reported Categories:</b> {categories_str}", styles['Normal']))


def add_geographic_info(story: List, data: Dict[str, Any]):
    """Add geographic and network information"""
    # Try to get info from ipinfo or other sources
    ipinfo = data.get('ipinfo', {})
    if not isinstance(ipinfo, dict):
        ipinfo = {}

    abuse = data.get('abuseipdb', {})
    if not isinstance(abuse, dict):
        abuse = {}

    geo_data = [["Attribute", "Value"]]

    if ipinfo.get('found'):
        geo_data.append(["City", str(ipinfo.get('city', 'N/A'))])
        geo_data.append(["Region", str(ipinfo.get('region', 'N/A'))])
        geo_data.append(["Country", str(ipinfo.get('country', 'N/A'))])
        geo_data.append(["Location", str(ipinfo.get('loc', 'N/A'))])
        geo_data.append(["Organization", str(ipinfo.get('org', 'N/A'))])

        # Safely get ASN
        asn_data = ipinfo.get('asn', {})
        if isinstance(asn_data, dict):
            geo_data.append(["ASN", str(asn_data.get('asn', 'N/A'))])
        else:
            geo_data.append(["ASN", str(asn_data) if asn_data else 'N/A'])

        geo_data.append(["Timezone", str(ipinfo.get('timezone', 'N/A'))])

        privacy = ipinfo.get('privacy', {})
        if isinstance(privacy, dict) and privacy:
            geo_data.append(["VPN", str(privacy.get('vpn', False))])
            geo_data.append(["Proxy", str(privacy.get('proxy', False))])
            geo_data.append(["Tor", str(privacy.get('tor', False))])
            geo_data.append(["Relay", str(privacy.get('relay', False))])
            geo_data.append(["Hosting", str(privacy.get('hosting', False))])
    elif abuse.get('found'):
        geo_data.append(["Country", str(abuse.get('country_name', 'N/A'))])
        geo_data.append(["ISP", str(abuse.get('isp', 'N/A'))])
        geo_data.append(["Usage Type", str(abuse.get('usage_type', 'N/A'))])

    geo_table = Table(geo_data, colWidths=[2*inch, 4*inch])
    geo_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
    ]))
    story.append(geo_table)


def add_shodan_section(story: List, shodan_data: Dict[str, Any]):
    """Add Shodan section to report"""
    heading_style = styles['Heading3']
    story.append(Paragraph("Shodan Network Intelligence", heading_style))
    story.append(Spacer(1, 10))

    summary_text = f"""
    <b>Organization:</b> {str(shodan_data.get('org', 'N/A'))}<br/>
    <b>ISP:</b> {str(shodan_data.get('isp', 'N/A'))}<br/>
    <b>ASN:</b> {str(shodan_data.get('asn', 'N/A'))}<br/>
    <b>Open Ports:</b> {len(shodan_data.get('ports', []))} detected<br/>
    <b>Last Update:</b> {str(shodan_data.get('last_update', 'N/A'))}
    """
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 10))

    # Ports and services
    ports = shodan_data.get('ports', [])
    if ports:
        ports_str = ', '.join(map(str, ports[:20]))
        story.append(Paragraph(f"<b>Open Ports:</b> {ports_str}", styles['Normal']))
        story.append(Spacer(1, 5))

    # Vulnerabilities
    vulns = shodan_data.get('vulns', [])
    if vulns:
        story.append(Paragraph(f"<b>Known Vulnerabilities:</b>", styles['Normal']))
        vuln_text = "<br/>".join([f"• {str(v)}" for v in vulns[:10]])
        story.append(Paragraph(vuln_text, styles['Normal']))


def add_threat_feeds_section(story: List, feeds_data: Dict[str, Any]):
    """Add threat feeds section to report"""
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch

    heading_style = styles['Heading2']
    story.append(Paragraph("THREAT FEED CORRELATION", heading_style))
    story.append(Spacer(1, 10))

    if not feeds_data.get('found'):
        story.append(Paragraph("IP not found in any threat intelligence feeds.", styles['Normal']))
        return

    feed_count = feeds_data.get('feed_count', 0)
    feeds = feeds_data.get('feeds', [])

    summary_text = f"""
    <b>Total Feeds Matched:</b> {feed_count}<br/>
    <b>Risk Assessment:</b> IP address found in multiple threat intelligence feeds indicating potential malicious activity.
    """
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 15))

    # Create feed table
    if feeds:
        feed_data = [["Feed Name", "Category", "Type", "Description"]]

        for feed in feeds[:15]:  # Top 15 feeds
            feed_data.append([
                str(feed.get('name', 'Unknown'))[:25],
                str(feed.get('category', 'N/A')),
                str(feed.get('type', 'N/A')),
                str(feed.get('description', 'N/A'))[:40]
            ])

        feed_table = Table(feed_data, colWidths=[2*inch, 1.2*inch, 0.8*inch, 2.5*inch])
        feed_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fff3cd')])
        ]))
        story.append(feed_table)

        if feed_count > 15:
            story.append(Spacer(1, 5))
            story.append(Paragraph(f"<i>...and {feed_count - 15} more feeds</i>", styles['Normal']))


def add_dnsbl_section(story: List, dnsbl_data: Dict[str, Any]):
    """Add DNSBL section to report"""
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch

    heading_style = styles['Heading2']
    story.append(Paragraph("DNS BLACKLIST (DNSBL) ANALYSIS", heading_style))
    story.append(Spacer(1, 10))

    total_checked = dnsbl_data.get('total_checked', 0)
    listing_count = dnsbl_data.get('listing_count', 0)
    blacklist_count = dnsbl_data.get('blacklist_count', listing_count)
    is_whitelisted = dnsbl_data.get('is_whitelisted', False)
    threat_level = str(dnsbl_data.get('threat_level', 'UNKNOWN'))

    # Summary
    summary_text = f"""
    <b>DNSBLs Checked:</b> {total_checked}<br/>
    <b>Blacklist Entries:</b> {blacklist_count}<br/>
    <b>Whitelisted:</b> {'Yes' if is_whitelisted else 'No'}<br/>
    <b>Threat Level:</b> <font color="{'red' if threat_level in ['CRITICAL', 'HIGH'] else 'orange' if threat_level == 'MEDIUM' else 'green'}">{threat_level}</font><br/>
    """
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 15))

    # Listings table
    listings = dnsbl_data.get('listed_in', [])
    blacklist_entries = [l for l in listings if l.get('category') != 'whitelist']

    if blacklist_entries:
        story.append(Paragraph("<b>Blacklist Entries:</b>", styles['Normal']))
        story.append(Spacer(1, 5))

        dnsbl_table_data = [["DNSBL Name", "Category", "Description"]]

        for entry in blacklist_entries[:20]:  # Top 20
            dnsbl_table_data.append([
                str(entry.get('name', 'Unknown'))[:30],
                str(entry.get('category', 'N/A')),
                str(entry.get('description', 'N/A'))[:45]
            ])

        dnsbl_table = Table(dnsbl_table_data, colWidths=[2.2*inch, 1.2*inch, 3*inch])
        dnsbl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ffebee')])
        ]))
        story.append(dnsbl_table)

        if blacklist_count > 20:
            story.append(Spacer(1, 5))
            story.append(Paragraph(f"<i>...and {blacklist_count - 20} more blacklist entries</i>", styles['Normal']))
    else:
        story.append(Paragraph("<font color='green'><b>✓ No blacklist entries found</b></font>", styles['Normal']))


def add_otx_section(story: List, otx_data: Dict[str, Any]):
    """Add AlienVault OTX section to report"""
    heading_style = styles['Heading3']
    story.append(Paragraph("AlienVault OTX Intelligence", heading_style))
    story.append(Spacer(1, 10))

    pulse_count = otx_data.get('pulse_count', 0)
    malware_families = otx_data.get('malware_families', [])
    attack_ids = otx_data.get('attack_ids', [])

    malware_str = ', '.join([str(m) for m in malware_families[:5]])
    attack_str = ', '.join([str(a) for a in attack_ids[:5]])

    summary_text = f"""
    <b>Threat Pulses:</b> {pulse_count}<br/>
    <b>Malware Families:</b> {malware_str if malware_str else 'N/A'}<br/>
    <b>Attack IDs:</b> {attack_str if attack_str else 'N/A'}
    """
    story.append(Paragraph(summary_text, styles['Normal']))


def generate_recommendations(threat_score: int, data: Dict[str, Any]) -> str:
    """Generate recommendations based on threat score and data"""
    recommendations = ""

    if threat_score >= 70:
        recommendations += """
        <b><font color='red'>CRITICAL THREAT - IMMEDIATE ACTION REQUIRED</font></b><br/><br/>

        <b>Recommended Actions:</b><br/>
        • <b>Block immediately</b> at firewall and perimeter devices<br/>
        • Add to IPS/IDS signature database<br/>
        • Review all logs for communications with this IP<br/>
        • Investigate any systems that have communicated with this IP<br/>
        • Report to incident response team<br/>
        • Consider threat hunting for related indicators<br/>
        • Update SIEM correlation rules<br/><br/>
        """
    elif threat_score >= 50:
        recommendations += """
        <b><font color='orange'>HIGH RISK - PROMPT ACTION ADVISED</font></b><br/><br/>

        <b>Recommended Actions:</b><br/>
        • Block at network perimeter<br/>
        • Enable enhanced logging for this IP<br/>
        • Review recent communications<br/>
        • Add to watch list<br/>
        • Schedule follow-up analysis in 24-48 hours<br/><br/>
        """
    elif threat_score >= 30:
        recommendations += """
        <b><font color='orange'>MEDIUM RISK - MONITORING RECOMMENDED</font></b><br/><br/>

        <b>Recommended Actions:</b><br/>
        • Add to monitoring/watch list<br/>
        • Enable logging for this IP<br/>
        • Review periodically<br/>
        • Consider blocking if suspicious activity detected<br/><br/>
        """
    else:
        recommendations += """
        <b><font color='green'>LOW RISK - STANDARD MONITORING</font></b><br/><br/>

        <b>Recommended Actions:</b><br/>
        • Continue standard monitoring<br/>
        • No immediate action required<br/>
        • Re-evaluate if behavior changes<br/><br/>
        """

    # Add specific recommendations based on findings
    recommendations += "<b>Specific Considerations:</b><br/>"

    if 'virustotal' in data and data['virustotal'].get('malicious', 0) > 0:
        recommendations += "• Multiple AV vendors detected malicious activity - high confidence indicator<br/>"

    if 'dnsbl' in data and data['dnsbl'].get('blacklist_count', 0) > 5:
        recommendations += "• Multiple DNSBL listings indicate established reputation as malicious<br/>"

    if 'threat_feeds' in data and data['threat_feeds'].get('feed_count', 0) > 0:
        recommendations += "• Presence in threat intelligence feeds confirms active threat campaigns<br/>"

    if 'abuseipdb' in data and data['abuseipdb'].get('confidence_score', 0) > 75:
        recommendations += "• High abuse confidence score from community reports<br/>"

    recommendations += "<br/><b>Report Distribution:</b> Share with SOC team, incident response, and threat intelligence analysts."

    return recommendations
