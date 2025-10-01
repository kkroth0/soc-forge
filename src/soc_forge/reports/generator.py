"""
Report Generator
Generate various types of reports from IP analysis results
"""

import os
from datetime import datetime
from typing import Dict, Any, List
from dataclasses import dataclass
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus.flowables import HRFlowable
import json
from ..utils.threat_scoring import ThreatScorer
from . import report_sections


@dataclass
class ReportMetadata:
    """Report metadata"""
    title: str
    report_type: str
    generated_at: datetime
    analyst: str
    ips_analyzed: List[str]
    sources_used: List[str]


class ReportGenerator:
    """Generate various types of analysis reports"""
    
    def __init__(self, output_dir: str = "outputs/reports"):
        self.output_dir = output_dir
        self.styles = getSampleStyleSheet()
        
        # Custom styles
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'], 
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
        
        self.threat_high_style = ParagraphStyle(
            'ThreatHigh',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontName='Helvetica-Bold'
        )
        
        self.threat_medium_style = ParagraphStyle(
            'ThreatMedium',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontName='Helvetica-Bold'
        )
        
        self.threat_low_style = ParagraphStyle(
            'ThreatLow',
            parent=self.styles['Normal'],
            textColor=colors.green,
            fontName='Helvetica-Bold'
        )
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_executive_summary(self, analysis_results: Dict[str, Any]) -> str:
        """Generate executive summary report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"executive_summary_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=letter, topMargin=1*inch)
        story = []
        
        # Title
        story.append(Paragraph(" SOC FORGE - Executive Threat Assessment", self.title_style))
        story.append(Spacer(1, 20))
        
        # Metadata
        story.append(Paragraph("Report Summary", self.heading_style))
        summary_data = [
            ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["IPs Analyzed:", str(len(analysis_results))],
            ["Report Type:", "Executive Summary"],
            ["Classification:", "CONFIDENTIAL"]
        ]
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.blackColor),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        # Calculate threat statistics
        threat_stats = ThreatScorer.calculate_threat_statistics(analysis_results)
        
        executive_text = f"""
        This report provides a high-level assessment of {len(analysis_results)} IP addresses analyzed 
        using multiple threat intelligence sources. The analysis identified:
        
        • {threat_stats['high_risk']} HIGH RISK indicators requiring immediate attention
        • {threat_stats['medium_risk']} MEDIUM RISK indicators for monitoring  
        • {threat_stats['low_risk']} LOW RISK or clean indicators
        
        Key threat vectors identified include malware communication, botnet activity, 
        scanning behavior, and abuse reports. Immediate remediation is recommended for 
        high-risk indicators.
        """
        
        story.append(Paragraph(executive_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Risk Assessment Table
        story.append(Paragraph("Risk Assessment Breakdown", self.heading_style))
        
        risk_data = [["Risk Level", "Count", "Percentage", "Action Required"]]
        total_ips = len(analysis_results)
        
        risk_data.append([
            "HIGH RISK", 
            str(threat_stats['high_risk']),
            f"{(threat_stats['high_risk']/total_ips)*100:.1f}%",
            "Immediate blocking/investigation"
        ])
        
        risk_data.append([
            "MEDIUM RISK",
            str(threat_stats['medium_risk']), 
            f"{(threat_stats['medium_risk']/total_ips)*100:.1f}%",
            "Enhanced monitoring"
        ])
        
        risk_data.append([
            "LOW RISK",
            str(threat_stats['low_risk']),
            f"{(threat_stats['low_risk']/total_ips)*100:.1f}%", 
            "Standard monitoring"
        ])
        
        risk_table = Table(risk_data, colWidths=[1.5*inch, 1*inch, 1*inch, 2.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(risk_table)
        story.append(Spacer(1, 20))
        
        # High Priority IPs
        high_priority_ips = self._get_high_priority_ips(analysis_results)
        if high_priority_ips:
            story.append(Paragraph("High Priority Indicators", self.heading_style))
            
            priority_data = [["IP Address", "Threat Score", "Key Findings", "Recommendation"]]
            for ip_info in high_priority_ips[:10]:  # Top 10
                priority_data.append([
                    ip_info['ip'],
                    str(ip_info['threat_score']),
                    ip_info['findings'][:50] + "..." if len(ip_info['findings']) > 50 else ip_info['findings'],
                    "Block immediately"
                ])
            
            priority_table = Table(priority_data, colWidths=[1.5*inch, 1*inch, 2.5*inch, 1*inch])
            priority_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(priority_table)
        
        # Build PDF
        doc.build(story)
        return filepath
    
    def generate_technical_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate detailed technical report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"technical_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=0.75*inch)
        story = []
        
        # Title page
        story.append(Paragraph("SOC Forge - Technical Analysis Report", self.title_style))
        story.append(Spacer(1, 30))
        
        # Report metadata
        story.append(Paragraph("Report Information", self.heading_style))
        
        metadata_text = f"""
        <b>Generated:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br/>
        <b>Analysis Scope:</b> {len(analysis_results)} IP addresses<br/>
        <b>Classification:</b> CONFIDENTIAL - SOC Internal Use<br/>
        <b>Analyst:</b> SOC Forge Automated Analysis<br/>
        """
        
        story.append(Paragraph(metadata_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Methodology section
        story.append(Paragraph("Analysis Methodology", self.heading_style))
        methodology_text = """
        This technical report presents detailed findings from multi-source threat intelligence analysis.
        Each IP address was analyzed against the following sources:
        
        • VirusTotal - Malware detection and reputation scoring
        • AbuseIPDB - Abuse reporting and confidence metrics  
        • GreyNoise - Internet scanning behavior analysis
        • ThreatFox - IOC correlation and malware family attribution
        • IPInfo - Geolocation and network infrastructure analysis
        
        Threat scoring incorporates weighted metrics from each source to provide comprehensive risk assessment.
        """
        
        story.append(Paragraph(methodology_text, self.styles['Normal']))
        story.append(PageBreak())
        
        # Detailed IP Analysis
        story.append(Paragraph("Detailed IP Analysis", self.heading_style))
        
        for ip, result in analysis_results.items():
            if not result.success:
                continue
                
            story.append(Paragraph(f"Analysis: {ip}", self.heading_style))
            
            # Calculate threat score for this IP
            threat_score = ThreatScorer.calculate_ip_threat_score(result.data)
            threat_level = ThreatScorer.get_threat_level(threat_score)
            
            # IP summary table
            ip_summary = [
                ["Attribute", "Value"],
                ["IP Address", ip],
                ["Threat Score", f"{threat_score}/100"],
                ["Risk Level", threat_level],
                ["Analysis Time", f"{result.analysis_time_ms}ms"],
                ["Sources Successful", f"{len(result.sources_successful)}/{len(result.sources_queried)}"]
            ]
            
            ip_table = Table(ip_summary, colWidths=[2*inch, 3*inch])
            ip_table.setStyle(self._get_table_style(threat_level))
            story.append(ip_table)
            story.append(Spacer(1, 10))
            
            # Source-specific findings
            for source, data in result.data.items():
                if isinstance(data, dict) and data.get('found'):
                    story.append(Paragraph(f"{source.title()} Findings", self.styles['Heading3']))
                    
                    # Format source-specific data
                    source_findings = self._format_source_findings(source, data)
                    story.append(Paragraph(source_findings, self.styles['Normal']))
                    story.append(Spacer(1, 10))
            
            story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
            story.append(Spacer(1, 15))
        
        # Build PDF
        doc.build(story)
        return filepath
    
    def generate_json_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate machine-readable JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"analysis_results_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        # Prepare data for JSON serialization
        json_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_type": "technical_analysis", 
                "version": "2.0.0",
                "total_ips": len(analysis_results)
            },
            "results": {}
        }
        
        for ip, result in analysis_results.items():
            json_data["results"][ip] = {
                "success": result.success,
                "analysis_time_ms": result.analysis_time_ms,
                "sources_queried": result.sources_queried,
                "sources_successful": result.sources_successful,
                "threat_score": ThreatScorer.calculate_ip_threat_score(result.data),
                "data": result.data,
                "error": result.error
            }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        return filepath
    
    
    def _get_high_priority_ips(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get high priority IPs for executive summary"""
        high_priority = []
        
        for ip, result in results.items():
            if not result.success:
                continue

            threat_score = ThreatScorer.calculate_ip_threat_score(result.data)
            if threat_score >= 70:
                findings = ThreatScorer.extract_key_findings(result.data)
                high_priority.append({
                    "ip": ip,
                    "threat_score": threat_score,
                    "findings": findings
                })
        
        # Sort by threat score descending
        return sorted(high_priority, key=lambda x: x['threat_score'], reverse=True)
    
    def _extract_key_findings(self, data: Dict[str, Any]) -> str:
        """Extract key findings for summary"""
        findings = []
        
        if 'virustotal' in data and data['virustotal'].get('malicious', 0) > 0:
            findings.append(f"VirusTotal: {data['virustotal']['malicious']} detections")
        
        if 'abuseipdb' in data and data['abuseipdb'].get('confidence_score', 0) > 50:
            findings.append(f"AbuseIPDB: {data['abuseipdb']['confidence_score']}% confidence")
        
        if 'greynoise' in data and data['greynoise'].get('malicious'):
            findings.append("GreyNoise: Malicious classification")
        
        if 'threatfox' in data and data['threatfox'].get('ioc_count', 0) > 0:
            findings.append(f"ThreatFox: {data['threatfox']['ioc_count']} IOCs")
        
        return "; ".join(findings) if findings else "Multiple indicators"
    
    def _format_source_findings(self, source: str, data: Dict[str, Any]) -> str:
        """Format findings from specific source"""
        if source == 'virustotal':
            content = f"""
            Detection ratio: {data.get('vendor_detection_ratio', '0/0')}<br/>
            Malicious detections: {data.get('malicious', 0)}<br/>
            Suspicious detections: {data.get('suspicious', 0)}<br/>
            Harmless detections: {data.get('harmless', 0)}<br/>
            Total engines: {data.get('total_engines', 0)}<br/>
            Reputation score: {data.get('reputation', 'N/A')}<br/>
            """

            # Add top detecting engines
            engines_detected = data.get('engines_detected', [])
            if engines_detected:
                content += "<br/><b>Top Detecting Engines:</b><br/>"
                for engine in engines_detected[:5]:  # Top 5
                    content += f"• {engine.get('engine', 'Unknown')}: {engine.get('result', 'N/A')}<br/>"

            return content
        elif source == 'abuseipdb':
            return f"""
            Abuse confidence: {data.get('confidence_score', 0)}%<br/>
            Total reports: {data.get('total_reports', 0)}<br/>
            Country: {data.get('country_name', 'N/A')}<br/>
            ISP: {data.get('isp', 'N/A')[:50]}...
            """
        elif source == 'greynoise':
            return f"""
            Classification: {data.get('classification', 'Unknown')}<br/>
            First seen: {data.get('first_seen', 'N/A')}<br/>
            Actor: {data.get('actor', 'N/A')}<br/>
            Tags: {', '.join(data.get('tags', [])[:5])}
            """
        elif source == 'threatfox':
            return f"""
            IOCs found: {data.get('ioc_count', 0)}<br/>
            Malware families: {', '.join(data.get('malware_families', [])[:3])}<br/>
            Threat types: {', '.join(data.get('threat_types', [])[:3])}<br/>
            Confidence level: {data.get('confidence_level', 0):.1f}%
            """
        elif source == 'ipinfo':
            return f"""
            Location: {data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}<br/>
            Organization: {data.get('organization', 'N/A')[:50]}...<br/>
            ASN: {data.get('asn', 'N/A')}<br/>
            VPN/Proxy detected: {data.get('privacy_vpn', False) or data.get('privacy_proxy', False)}
            """
        
        return "Data available"
    
    def _get_table_style(self, threat_level: str) -> TableStyle:
        """Get table style based on threat level"""
        if threat_level == "HIGH RISK":
            header_color = colors.red
        elif threat_level == "MEDIUM RISK":
            header_color = colors.orange
        else:
            header_color = colors.green
        
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), header_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ])

    def generate_comprehensive_report(self, ip: str, analysis_data: Dict[str, Any]) -> str:
        """
        Generate comprehensive threat intelligence report for a single IP

        Args:
            ip: IP address analyzed
            analysis_data: Complete analysis data from all sources

        Returns:
            Path to generated PDF report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_intel_report_{ip.replace('.', '_')}_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []

        # Calculate threat score
        threat_score = ThreatScorer.calculate_ip_threat_score(analysis_data)
        threat_level = self._get_threat_level_text(threat_score)
        threat_color = self._get_threat_color(threat_score)

        # ===== TITLE PAGE =====
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph("THREAT INTELLIGENCE REPORT", self.title_style))
        story.append(Spacer(1, 0.3*inch))

        # Report header box
        header_data = [
            ["Target IP Address:", ip],
            ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Threat Score:", f"{threat_score}/100"],
            ["Risk Level:", threat_level],
            ["Classification:", "CONFIDENTIAL - SOC INTERNAL USE"],
            ["Platform:", "SOC Forge v3.0"]
        ]

        header_table = Table(header_data, colWidths=[2.5*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (1, 3), (1, 3), threat_color),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTNAME', (1, 3), (1, 3), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('BOX', (0, 0), (-1, -1), 2, colors.HexColor('#34495e')),
            ('LINEBELOW', (0, 0), (-1, 0), 1, colors.HexColor('#34495e'))
        ]))
        story.append(header_table)
        story.append(Spacer(1, 0.5*inch))

        # ===== EXECUTIVE SUMMARY =====
        story.append(Paragraph("EXECUTIVE SUMMARY", self.heading_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3498db')))
        story.append(Spacer(1, 10))

        # Generate executive summary text
        exec_summary = self._generate_executive_summary_text(ip, analysis_data, threat_score, threat_level)
        story.append(Paragraph(exec_summary, self.styles['Normal']))
        story.append(Spacer(1, 20))

        # ===== REPUTATION ANALYSIS =====
        story.append(PageBreak())
        story.append(Paragraph("MULTI-SOURCE REPUTATION ANALYSIS", self.heading_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3498db')))
        story.append(Spacer(1, 10))

        # Create reputation summary table
        self._add_reputation_table(story, analysis_data)
        story.append(Spacer(1, 20))

        # ===== VIRUSTOTAL DETAILED ANALYSIS =====
        vt_data = analysis_data.get('virustotal', {})
        if isinstance(vt_data, dict) and vt_data.get('found'):
            report_sections.add_virustotal_section(story, vt_data)
            story.append(Spacer(1, 20))

        # ===== ABUSEIPDB ANALYSIS =====
        abuse_data = analysis_data.get('abuseipdb', {})
        if isinstance(abuse_data, dict) and abuse_data.get('found'):
            report_sections.add_abuseipdb_section(story, abuse_data)
            story.append(Spacer(1, 20))

        # ===== GEOGRAPHIC & NETWORK INFO =====
        story.append(PageBreak())
        story.append(Paragraph("GEOGRAPHIC & NETWORK INFORMATION", self.heading_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3498db')))
        story.append(Spacer(1, 10))
        report_sections.add_geographic_info(story, analysis_data)
        story.append(Spacer(1, 20))

        # ===== SHODAN RESULTS =====
        shodan_data = analysis_data.get('shodan', {})
        if isinstance(shodan_data, dict) and shodan_data.get('found'):
            report_sections.add_shodan_section(story, shodan_data)
            story.append(Spacer(1, 20))

        # ===== THREAT FEEDS RESULTS =====
        story.append(PageBreak())
        threat_feeds_data = analysis_data.get('threat_feeds', {})
        if isinstance(threat_feeds_data, dict):
            report_sections.add_threat_feeds_section(story, threat_feeds_data)
            story.append(Spacer(1, 20))

        # ===== DNSBL RESULTS =====
        dnsbl_data = analysis_data.get('dnsbl', {})
        if isinstance(dnsbl_data, dict):
            report_sections.add_dnsbl_section(story, dnsbl_data)
            story.append(Spacer(1, 20))

        # ===== ALIENVAULT OTX =====
        otx_data = analysis_data.get('otx', {})
        if isinstance(otx_data, dict) and otx_data.get('found'):
            story.append(PageBreak())
            report_sections.add_otx_section(story, otx_data)

        # ===== RECOMMENDATIONS =====
        story.append(PageBreak())
        story.append(Paragraph("RECOMMENDATIONS & ACTIONS", self.heading_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3498db')))
        story.append(Spacer(1, 10))
        recommendations = report_sections.generate_recommendations(threat_score, analysis_data)
        story.append(Paragraph(recommendations, self.styles['Normal']))

        # Build PDF
        doc.build(story)
        return filepath

    def _get_threat_level_text(self, score: int) -> str:
        """Get threat level text from score"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "MINIMAL"

    def _get_threat_color(self, score: int) -> colors.Color:
        """Get color for threat score"""
        if score >= 70:
            return colors.HexColor('#e74c3c')
        elif score >= 50:
            return colors.HexColor('#e67e22')
        elif score >= 30:
            return colors.HexColor('#f39c12')
        else:
            return colors.HexColor('#27ae60')

    def _generate_executive_summary_text(self, ip: str, data: Dict[str, Any], score: int, level: str) -> str:
        """Generate executive summary paragraph"""
        summary = f"""
        This report presents a comprehensive threat intelligence analysis of IP address <b>{ip}</b>.
        The analysis was conducted using multiple authoritative threat intelligence sources and databases.
        <br/><br/>
        <b>Overall Assessment:</b> The target IP received a threat score of <b>{score}/100</b>,
        classified as <b><font color="{'red' if score >= 70 else 'orange' if score >= 30 else 'green'}">{level}</font></b> risk.
        <br/><br/>
        """

        # Add key findings
        findings = []

        vt = data.get('virustotal', {})
        if isinstance(vt, dict) and vt.get('malicious', 0) > 0:
            findings.append(f"VirusTotal flagged this IP with {vt['malicious']} malicious detections")

        abuse = data.get('abuseipdb', {})
        if isinstance(abuse, dict) and abuse.get('confidence_score', 0) > 50:
            findings.append(f"AbuseIPDB reports {abuse['confidence_score']}% abuse confidence with {abuse.get('total_reports', 0)} reports")

        tf_data = data.get('threat_feeds', {})
        if isinstance(tf_data, dict) and tf_data.get('found'):
            findings.append(f"Found in {tf_data.get('feed_count', 0)} threat intelligence feeds")

        dnsbl = data.get('dnsbl', {})
        if isinstance(dnsbl, dict) and dnsbl.get('listing_count', 0) > 0:
            blacklist_count = dnsbl.get('blacklist_count', dnsbl.get('listing_count', 0))
            findings.append(f"Listed in {blacklist_count} DNS blacklists")

        if findings:
            summary += "<b>Key Findings:</b><br/>"
            for finding in findings:
                summary += f"• {finding}<br/>"

        return summary

    def _add_reputation_table(self, story: List, data: Dict[str, Any]):
        """Add reputation summary table"""
        rep_data = [["Source", "Verdict", "Confidence", "Details"]]

        # VirusTotal
        vt = data.get('virustotal', {})
        if isinstance(vt, dict) and vt.get('found'):
            malicious = vt.get('malicious', 0)
            verdict = "Malicious" if malicious > 0 else "Clean"
            verdict_color = 'red' if malicious > 0 else 'green'
            confidence = f"{malicious}/{vt.get('total_engines', 0)}"
            details = f"{vt.get('vendor_detection_ratio', 'N/A')}"
            rep_data.append([
                "VirusTotal",
                Paragraph(f"<font color='{verdict_color}'>{verdict}</font>", self.styles['Normal']),
                confidence,
                details
            ])

        # AbuseIPDB
        abuse = data.get('abuseipdb', {})
        if isinstance(abuse, dict) and abuse.get('found'):
            conf_score = abuse.get('confidence_score', 0)
            verdict = "Malicious" if conf_score >= 75 else "Suspicious" if conf_score >= 25 else "Clean"
            verdict_color = 'red' if conf_score >= 75 else 'orange' if conf_score >= 25 else 'green'
            rep_data.append([
                "AbuseIPDB",
                Paragraph(f"<font color='{verdict_color}'>{verdict}</font>", self.styles['Normal']),
                f"{conf_score}%",
                f"{abuse.get('total_reports', 0)} reports"
            ])

        # GreyNoise
        gn = data.get('greynoise', {})
        if isinstance(gn, dict) and gn.get('found'):
            classification = str(gn.get('classification', 'unknown'))
            verdict_color = 'red' if classification == 'malicious' else 'green' if classification == 'benign' else 'orange'
            rep_data.append([
                "GreyNoise",
                Paragraph(f"<font color='{verdict_color}'>{classification.title()}</font>", self.styles['Normal']),
                "N/A",
                str(gn.get('name', 'Internet Scanner'))[:30]
            ])

        # ThreatFox
        tf = data.get('threatfox', {})
        if isinstance(tf, dict) and tf.get('found') and tf.get('ioc_count', 0) > 0:
            malware_families = tf.get('malware_families', [])
            if isinstance(malware_families, list):
                families_str = ', '.join([str(f) for f in malware_families[:2]])
            else:
                families_str = str(malware_families)

            rep_data.append([
                "ThreatFox",
                Paragraph("<font color='red'>Malicious</font>", self.styles['Normal']),
                f"{tf.get('ioc_count', 0)} IOCs",
                families_str
            ])

        rep_table = Table(rep_data, colWidths=[1.5*inch, 1.2*inch, 1.2*inch, 2.5*inch])
        rep_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        story.append(rep_table)