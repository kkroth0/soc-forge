"""
Professional Threat Intelligence Report Generator
Generates enterprise-grade PDF reports with proper formatting
"""

import os
from datetime import datetime
from typing import Dict, Any, List
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, Frame, PageTemplate
)
from reportlab.platypus.flowables import HRFlowable
from reportlab.pdfgen import canvas
from ..utils.threat_scoring import ThreatScorer
from . import report_sections
from .translations import get_translation


class NumberedCanvas(canvas.Canvas):
    """Custom canvas for page numbers and footers"""

    def __init__(self, *args, **kwargs):
        self.language = kwargs.pop('language', 'ENG')
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, num_pages):
        page_num = self._pageNumber

        # Footer line
        self.setStrokeColor(colors.HexColor('#2c3e50'))
        self.setLineWidth(0.5)
        self.line(1*cm, 1.5*cm, A4[0]-1*cm, 1.5*cm)

        # Classification marking
        self.setFont('Helvetica-Bold', 8)
        self.setFillColor(colors.HexColor('#e74c3c'))
        classification = get_translation(self.language, 'classification')
        self.drawCentredString(A4[0]/2, 1*cm, classification)

        # Page number
        self.setFont('Helvetica', 9)
        self.setFillColor(colors.HexColor('#2c3e50'))
        page_text = get_translation(self.language, 'footer_page')
        of_text = get_translation(self.language, 'footer_of')
        self.drawRightString(A4[0]-1*cm, 1*cm, f"{page_text} {page_num} {of_text} {num_pages}")

        # Document ID
        self.setFont('Helvetica', 8)
        self.setFillColor(colors.HexColor('#7f8c8d'))
        doc_id = f"SOC-TI-{datetime.now().strftime('%Y%m%d')}"
        self.drawString(1*cm, 1*cm, doc_id)


class ProfessionalThreatReport:
    """Generate professional threat intelligence reports"""

    def __init__(self, output_dir: str = "outputs/reports", language: str = "ENG"):
        self.output_dir = output_dir
        self.language = language.upper()
        self.styles = getSampleStyleSheet()
        os.makedirs(output_dir, exist_ok=True)

        # Custom styles
        self._create_custom_styles()

    def t(self, key: str, default: str = None) -> str:
        """Shorthand for getting translation"""
        return get_translation(self.language, key, default)

    def _create_custom_styles(self):
        """Create custom paragraph styles"""

        # Cover title
        self.styles.add(ParagraphStyle(
            name='CoverTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Cover subtitle
        self.styles.add(ParagraphStyle(
            name='CoverSubtitle',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName='Helvetica'
        ))

        # Section heading
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=15,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            borderWidth=2,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=10,
            backColor=colors.HexColor('#ecf0f1')
        ))

        # Subsection heading
        self.styles.add(ParagraphStyle(
            name='SubsectionHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=10,
            spaceBefore=15,
            fontName='Helvetica-Bold'
        ))

        # Body justified
        self.styles.add(ParagraphStyle(
            name='BodyJustified',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=10
        ))

        # Classification box
        self.styles.add(ParagraphStyle(
            name='Classification',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.white,
            backColor=colors.HexColor('#e74c3c'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            borderPadding=10
        ))

    def generate_report(self, ip: str, analysis_data: Dict[str, Any]) -> str:
        """Generate comprehensive professional report"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ThreatIntel_Report_{ip.replace('.', '-')}_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # Create document with custom canvas
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            topMargin=2*cm,
            bottomMargin=2.5*cm,
            leftMargin=2*cm,
            rightMargin=2*cm
        )

        story = []

        # Calculate threat score
        threat_score = ThreatScorer.calculate_ip_threat_score(analysis_data)
        threat_level = self._get_threat_level(threat_score)

        # ===== COVER PAGE =====
        self._add_cover_page(story, ip, threat_score, threat_level)
        story.append(PageBreak())

        # ===== DOCUMENT CONTROL =====
        self._add_document_control(story, ip)
        story.append(PageBreak())

        # ===== EXECUTIVE SUMMARY =====
        self._add_executive_summary(story, ip, analysis_data, threat_score, threat_level)
        story.append(PageBreak())

        # ===== TABLE OF CONTENTS (Manual) =====
        self._add_table_of_contents(story)
        story.append(PageBreak())

        # ===== THREAT ASSESSMENT =====
        self._add_threat_assessment(story, ip, analysis_data, threat_score, threat_level)
        story.append(PageBreak())

        # ===== DETAILED ANALYSIS =====
        self._add_detailed_analysis(story, analysis_data)

        # ===== RECOMMENDATIONS =====
        story.append(PageBreak())
        self._add_recommendations(story, threat_score, analysis_data)

        # ===== METHODOLOGY =====
        story.append(PageBreak())
        self._add_methodology(story)

        # ===== REFERENCES =====
        story.append(PageBreak())
        self._add_references(story)

        # Build PDF with custom canvas
        def make_canvas(*args, **kwargs):
            kwargs['language'] = self.language
            return NumberedCanvas(*args, **kwargs)

        doc.build(story, canvasmaker=make_canvas)
        return filepath

    def _add_cover_page(self, story: List, ip: str, score: int, level: str):
        """Add professional cover page"""

        # Classification banner
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(self.t('classification'), self.styles['Classification']))
        story.append(Spacer(1, 2*cm))

        # Main title
        story.append(Paragraph(self.t('title'), self.styles['CoverTitle']))
        story.append(Spacer(1, 0.5*cm))

        # Subtitle
        story.append(Paragraph(self.t('subtitle'), self.styles['CoverSubtitle']))
        story.append(Paragraph(f"<b>{ip}</b>", self.styles['CoverSubtitle']))
        story.append(Spacer(1, 2*cm))

        # Threat score box
        score_color = self._get_threat_color(score)
        score_box_data = [[f"{self.t('threat_score').upper()}: {score}/100"], [f"{self.t('risk_level').upper()}: {level}"]]
        score_table = Table(score_box_data, colWidths=[12*cm])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), score_color),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 16),
            ('PADDING', (0, 0), (-1, -1), 20),
            ('BOX', (0, 0), (-1, -1), 2, colors.white)
        ]))
        story.append(score_table)
        story.append(Spacer(1, 3*cm))

        # Document info
        doc_info = [
            [self.t('date') + ":", datetime.now().strftime("%B %d, %Y at %H:%M UTC")],
            [self.t('classification', 'Classification') + ":", self.t('classification')],
            [self.t('distribution') + ":", self.t('distribution_text')],
            [self.t('prepared_by') + ":", "SOC Forge Automated Threat Intelligence Platform v3.0"],
            [self.t('scope', 'Validity') + ":", "This assessment is valid for 24-48 hours"]
        ]

        info_table = Table(doc_info, colWidths=[5*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#2c3e50')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#bdc3c7')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
        ]))
        story.append(info_table)

    def _add_document_control(self, story: List, ip: str):
        """Add document control page"""

        story.append(Paragraph(self.t('doc_control'), self.styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))

        control_data = [
            [self.t('title', 'Document Title') + ":", f"{self.t('title')} - {ip}"],
            ["Document ID:", f"SOC-TI-{datetime.now().strftime('%Y%m%d-%H%M%S')}"],
            [self.t('version') + ":", "1.0"],
            [self.t('classification', 'Classification') + ":", self.t('classification')],
            [self.t('prepared_by', 'Author') + ":", "SOC Forge Automated TI Platform"],
            ["Review Date:", (datetime.now().replace(day=datetime.now().day + 1)).strftime("%Y-%m-%d")],
            [self.t('distribution') + ":", self.t('distribution_text')],
            ["Retention Period:", "90 days from generation date"]
        ]

        control_table = Table(control_data, colWidths=[5*cm, 12*cm])
        control_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#34495e')),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 8)
        ]))
        story.append(control_table)
        story.append(Spacer(1, 1*cm))

        # Purpose
        story.append(Paragraph(self.t('purpose').upper(), self.styles['SubsectionHeading']))
        purpose_text = self.t('purpose_text')
        story.append(Paragraph(purpose_text, self.styles['BodyJustified']))
        story.append(Spacer(1, 0.5*cm))

        # Scope
        story.append(Paragraph(self.t('scope').upper(), self.styles['SubsectionHeading']))
        scope_text = self.t('scope_text')
        story.append(Paragraph(scope_text, self.styles['BodyJustified']))

    def _add_executive_summary(self, story: List, ip: str, data: Dict[str, Any], score: int, level: str):
        """Add executive summary"""

        story.append(Paragraph(self.t('executive_summary').upper(), self.styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))

        # Summary paragraph
        summary_intro = f"""
        This report presents a threat intelligence assessment of IP address <b>{ip}</b> conducted on
        {datetime.now().strftime('%B %d, %Y')}. The target IP has been assigned a threat score of
        <b>{score}/100</b>, classified as <b>{level}</b> risk based on multi-source intelligence correlation.
        """
        story.append(Paragraph(summary_intro, self.styles['BodyJustified']))
        story.append(Spacer(1, 0.5*cm))

        # Key findings
        story.append(Paragraph(self.t('key_findings').upper(), self.styles['SubsectionHeading']))

        findings = self._extract_key_findings(data)
        if findings:
            for finding in findings:
                story.append(Paragraph(f"• {finding}", self.styles['Normal']))
        else:
            story.append(Paragraph("• No significant malicious indicators identified across threat intelligence sources", self.styles['Normal']))

        story.append(Spacer(1, 0.5*cm))

        # Recommendation summary
        story.append(Paragraph(self.t('recommendation_summary').upper(), self.styles['SubsectionHeading']))
        rec_summary = self._get_recommendation_summary(score)
        story.append(Paragraph(rec_summary, self.styles['BodyJustified']))

    def _add_table_of_contents(self, story: List):
        """Add table of contents"""

        story.append(Paragraph(self.t('toc'), self.styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))

        toc_data = [
            ["1.", self.t('executive_summary'), "3"],
            ["2.", self.t('threat_assessment'), "5"],
            ["3.", self.t('reputation_analysis'), "6"],
            ["4.", "Detailed Technical Analysis", "7"],
            ["  4.1", "VirusTotal Intelligence", "7"],
            ["  4.2", "AbuseIPDB Assessment", "8"],
            ["  4.3", self.t('dnsbl_results'), "9"],
            ["  4.4", self.t('threat_feeds'), "10"],
            ["  4.5", "Network Infrastructure", "11"],
            ["5.", self.t('recommendations'), "12"],
            ["6.", self.t('methodology'), "13"],
            ["7.", self.t('references'), "14"]
        ]

        toc_table = Table(toc_data, colWidths=[1.5*cm, 13*cm, 2*cm])
        toc_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (2, 0), (2, -1), 'RIGHT'),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
        ]))
        story.append(toc_table)

    def _add_threat_assessment(self, story: List, ip: str, data: Dict[str, Any], score: int, level: str):
        """Add threat assessment overview"""

        story.append(Paragraph(self.t('threat_overview'), self.styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))

        # Assessment summary table
        assessment_data = [
            [self.t('source', 'Assessment Criterion'), self.t('status', 'Result'), "Weight", self.t('findings', 'Finding')],
            [self.t('overall_assessment', 'Overall Threat Score'), f"{score}/100", "100%", level],
            ["VirusTotal Detections", self._get_vt_summary(data), "35%", self._get_vt_verdict(data)],
            ["AbuseIPDB Confidence", self._get_abuse_summary(data), "25%", self._get_abuse_verdict(data)],
            ["DNS Blacklists", self._get_dnsbl_summary(data), "20%", self._get_dnsbl_verdict(data)],
            [self.t('threat_feeds', 'Threat Feeds'), self._get_feeds_summary(data), "15%", self._get_feeds_verdict(data)],
            ["Network Infrastructure", self._get_network_summary(data), "5%", self._get_network_verdict(data)]
        ]

        assessment_table = Table(assessment_data, colWidths=[5*cm, 3*cm, 2*cm, 7*cm])
        assessment_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(assessment_table)

    def _add_detailed_analysis(self, story: List, data: Dict[str, Any]):
        """Add detailed technical analysis sections"""

        story.append(Paragraph("DETAILED TECHNICAL ANALYSIS", self.styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))

        # Multi-source reputation
        story.append(Paragraph(self.t('reputation_summary'), self.styles['SubsectionHeading']))
        self._add_reputation_comparison(story, data)
        story.append(Spacer(1, 0.5*cm))

        # Individual source sections
        vt_data = data.get('virustotal', {})
        if isinstance(vt_data, dict) and vt_data.get('found'):
            story.append(PageBreak())
            story.append(Paragraph("VirusTotal Intelligence", self.styles['SubsectionHeading']))
            report_sections.add_virustotal_section(story, vt_data)

        abuse_data = data.get('abuseipdb', {})
        if isinstance(abuse_data, dict) and abuse_data.get('found'):
            story.append(Spacer(1, 1*cm))
            story.append(Paragraph("AbuseIPDB Assessment", self.styles['SubsectionHeading']))
            report_sections.add_abuseipdb_section(story, abuse_data)

        # DNSBL Analysis
        dnsbl_data = data.get('dnsbl', {})
        if isinstance(dnsbl_data, dict):
            story.append(PageBreak())
            story.append(Paragraph(self.t('dnsbl_title'), self.styles['SubsectionHeading']))
            report_sections.add_dnsbl_section(story, dnsbl_data)

        # Threat Feeds
        tf_data = data.get('threat_feeds', {})
        if isinstance(tf_data, dict):
            story.append(Spacer(1, 1*cm))
            story.append(Paragraph(self.t('feeds_title'), self.styles['SubsectionHeading']))
            report_sections.add_threat_feeds_section(story, tf_data)

        # Network info
        story.append(PageBreak())
        story.append(Paragraph("Network Infrastructure Analysis", self.styles['SubsectionHeading']))
        report_sections.add_geographic_info(story, data)

        shodan_data = data.get('shodan', {})
        if isinstance(shodan_data, dict) and shodan_data.get('found'):
            story.append(Spacer(1, 1*cm))
            story.append(Paragraph("Shodan Network Intelligence", self.styles['SubsectionHeading']))
            report_sections.add_shodan_section(story, shodan_data)

    def _add_recommendations(self, story: List, score: int, data: Dict[str, Any]):
        """Add recommendations section"""

        story.append(Paragraph(self.t('recommendations_title'), self.styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))

        recommendations = report_sections.generate_recommendations(score, data)
        story.append(Paragraph(recommendations, self.styles['BodyJustified']))

    def _add_methodology(self, story: List):
        """Add methodology section"""

        story.append(Paragraph(self.t('methodology_title'), self.styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))

        # Data Collection
        methodology_text = f"""
        <b>{self.t('data_collection')}:</b> {self.t('data_collection_text')}<br/><br/>

        <b>{self.t('analysis_framework')}:</b> {self.t('analysis_framework_text')}
        """
        story.append(Paragraph(methodology_text, self.styles['BodyJustified']))

        # Analysis points
        analysis_points = self.t('analysis_points')
        if isinstance(analysis_points, list):
            for point in analysis_points:
                story.append(Paragraph(f"• {point}", self.styles['Normal']))
        story.append(Spacer(1, 0.5*cm))

        # Scoring Methodology
        scoring_text = f"""
        <b>{self.t('scoring_methodology')}:</b> {self.t('scoring_methodology_text')}
        """
        story.append(Paragraph(scoring_text, self.styles['BodyJustified']))

        # Scoring points
        scoring_points = self.t('scoring_points')
        if isinstance(scoring_points, list):
            for point in scoring_points:
                story.append(Paragraph(f"• {point}", self.styles['Normal']))
        story.append(Spacer(1, 0.5*cm))

        # Limitations
        limitations_text = f"""
        <b>{self.t('limitations')}:</b> {self.t('limitations_text')}
        """
        story.append(Paragraph(limitations_text, self.styles['BodyJustified']))

    def _add_references(self, story: List):
        """Add references section"""

        story.append(Paragraph(self.t('references_title'), self.styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))

        references = [
            [self.t('source'), self.t('feed_type', 'Type'), self.t('url'), "Purpose"],
            ["VirusTotal", "Commercial API", "https://www.virustotal.com", "Malware scanning & reputation"],
            ["AbuseIPDB", "Community DB", "https://www.abuseipdb.com", "Abuse reporting & confidence"],
            ["AlienVault OTX", "Open Threat Exchange", "https://otx.alienvault.com", "Threat pulse correlation"],
            ["ThreatFox", "abuse.ch Project", "https://threatfox.abuse.ch", "IOC database"],
            ["Shodan", "Search Engine", "https://www.shodan.io", "Network infrastructure"],
            ["Spamhaus", "DNSBL", "https://www.spamhaus.org", "Email reputation"],
            ["SORBS", "DNSBL", "http://www.sorbs.net", "Spam sources"],
            ["Barracuda", "DNSBL", "https://barracudacentral.org", "Reputation system"],
        ]

        ref_table = Table(references, colWidths=[3.5*cm, 3*cm, 6*cm, 4.5*cm])
        ref_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(ref_table)

        story.append(Spacer(1, 1*cm))
        story.append(Paragraph("ADDITIONAL RESOURCES", self.styles['SubsectionHeading']))

        additional_text = """
        For additional threat intelligence context and indicator enrichment:
        <br/>• MITRE ATT&CK Framework: https://attack.mitre.org
        <br/>• SANS Internet Storm Center: https://isc.sans.edu
        <br/>• Cisco Talos Intelligence: https://talosintelligence.com
        <br/>• GreyNoise: https://www.greynoise.io
        """
        story.append(Paragraph(additional_text, self.styles['Normal']))

    # Helper methods
    def _get_threat_level(self, score: int) -> str:
        if score >= 70: return self.t('CRITICAL')
        elif score >= 50: return self.t('HIGH')
        elif score >= 30: return self.t('MEDIUM')
        elif score >= 10: return self.t('LOW')
        else: return self.t('INFO', 'MINIMAL')

    def _get_threat_color(self, score: int) -> colors.Color:
        if score >= 70: return colors.HexColor('#c0392b')
        elif score >= 50: return colors.HexColor('#e74c3c')
        elif score >= 30: return colors.HexColor('#f39c12')
        else: return colors.HexColor('#27ae60')

    def _extract_key_findings(self, data: Dict[str, Any]) -> List[str]:
        findings = []

        vt = data.get('virustotal', {})
        if isinstance(vt, dict) and vt.get('malicious', 0) > 0:
            findings.append(f"VirusTotal: {vt['malicious']} security vendors flagged as malicious ({vt.get('vendor_detection_ratio', self.t('not_available', 'N/A'))})")

        abuse = data.get('abuseipdb', {})
        if isinstance(abuse, dict) and abuse.get('confidence_score', 0) > 50:
            findings.append(f"AbuseIPDB: {abuse['confidence_score']}% abuse confidence with {abuse.get('total_reports', 0)} community reports")

        dnsbl = data.get('dnsbl', {})
        if isinstance(dnsbl, dict):
            bl_count = dnsbl.get('blacklist_count', 0)
            if bl_count > 0:
                findings.append(f"DNS Blacklists: Listed in {bl_count} blacklist(s) out of {dnsbl.get('total_checked', 0)} checked")

        tf = data.get('threat_feeds', {})
        if isinstance(tf, dict) and tf.get('found'):
            findings.append(f"Threat Feeds: Found in {tf.get('feed_count', 0)} threat intelligence feeds")

        return findings

    def _get_recommendation_summary(self, score: int) -> str:
        if score >= 70:
            return "IMMEDIATE ACTION REQUIRED: Block at network perimeter, investigate all communications, report to incident response team."
        elif score >= 50:
            return "PROMPT ACTION ADVISED: Block at firewall, enable enhanced logging, review recent activity."
        elif score >= 30:
            return "MONITORING RECOMMENDED: Add to watchlist, enable logging, review periodically."
        else:
            return "STANDARD MONITORING: Continue normal operations, no immediate action required."

    def _add_reputation_comparison(self, story: List, data: Dict[str, Any]):
        """Add multi-source reputation comparison table"""
        from reportlab.platypus import Paragraph, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.units import cm

        rep_data = [[self.t('source'), self.t('status'), "Score/Confidence", self.t('details')]]

        # Add rows for each source
        vt = data.get('virustotal', {})
        if isinstance(vt, dict) and vt.get('found'):
            status = self.t('detected', 'Malicious') if vt.get('malicious', 0) > 0 else self.t('clean')
            is_malicious = vt.get('malicious', 0) > 0
            color_style = f"<font color='red'>{status}</font>" if is_malicious else f"<font color='green'>{status}</font>"
            rep_data.append([
                "VirusTotal",
                Paragraph(color_style, self.styles['Normal']),
                f"{vt.get('malicious', 0)}/{vt.get('total_engines', 0)}",
                vt.get('vendor_detection_ratio', self.t('not_available', 'N/A'))
            ])

        abuse = data.get('abuseipdb', {})
        if isinstance(abuse, dict) and abuse.get('found'):
            conf = abuse.get('confidence_score', 0)
            if conf >= 75:
                status = self.t('detected', 'Malicious')
                color = 'red'
            elif conf >= 25:
                status = "Suspicious"
                color = 'orange'
            else:
                status = self.t('clean')
                color = 'green'
            color_style = f"<font color='{color}'>{status}</font>"
            rep_data.append([
                "AbuseIPDB",
                Paragraph(color_style, self.styles['Normal']),
                f"{conf}%",
                f"{abuse.get('total_reports', 0)} reports"
            ])

        # Add more sources...

        rep_table = Table(rep_data, colWidths=[4*cm, 3*cm, 3*cm, 7*cm])
        rep_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ecf0f1')]),
            ('PADDING', (0, 0), (-1, -1), 6)
        ]))
        story.append(rep_table)

    # Placeholder helper methods for assessment summaries
    def _get_vt_summary(self, data):
        vt = data.get('virustotal', {})
        return f"{vt.get('malicious', 0)}/{vt.get('total_engines', 0)}" if isinstance(vt, dict) and vt.get('found') else self.t('not_available', 'N/A')

    def _get_vt_verdict(self, data):
        vt = data.get('virustotal', {})
        return self.t('detected', 'Malicious') if isinstance(vt, dict) and vt.get('malicious', 0) > 0 else self.t('clean')

    def _get_abuse_summary(self, data):
        abuse = data.get('abuseipdb', {})
        return f"{abuse.get('confidence_score', 0)}%" if isinstance(abuse, dict) and abuse.get('found') else self.t('not_available', 'N/A')

    def _get_abuse_verdict(self, data):
        abuse = data.get('abuseipdb', {})
        if isinstance(abuse, dict):
            conf = abuse.get('confidence_score', 0)
            return self.t('detected', 'Malicious') if conf >= 75 else "Suspicious" if conf >= 25 else self.t('clean')
        return self.t('unknown')

    def _get_dnsbl_summary(self, data):
        dnsbl = data.get('dnsbl', {})
        if isinstance(dnsbl, dict):
            return f"{dnsbl.get('blacklist_count', 0)}/{dnsbl.get('total_checked', 0)}"
        return self.t('not_available', 'N/A')

    def _get_dnsbl_verdict(self, data):
        dnsbl = data.get('dnsbl', {})
        if isinstance(dnsbl, dict):
            count = dnsbl.get('blacklist_count', 0)
            return self.t('blacklisted', 'Listed') if count > 0 else self.t('clean')
        return self.t('unknown')

    def _get_feeds_summary(self, data):
        tf = data.get('threat_feeds', {})
        return f"{tf.get('feed_count', 0)} feeds" if isinstance(tf, dict) else self.t('not_available', 'N/A')

    def _get_feeds_verdict(self, data):
        tf = data.get('threat_feeds', {})
        return self.t('detected', 'Found') if isinstance(tf, dict) and tf.get('found') else self.t('not_found')

    def _get_network_summary(self, data):
        ipinfo = data.get('ipinfo', {})
        if isinstance(ipinfo, dict) and ipinfo.get('found'):
            return ipinfo.get('org', self.t('unknown'))[:20]
        return self.t('not_available', 'N/A')

    def _get_network_verdict(self, data):
        ipinfo = data.get('ipinfo', {})
        if isinstance(ipinfo, dict):
            privacy = ipinfo.get('privacy', {})
            if isinstance(privacy, dict):
                if privacy.get('vpn') or privacy.get('proxy') or privacy.get('tor'):
                    return "Suspicious"
        return "Normal"
