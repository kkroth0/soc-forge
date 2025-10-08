"""
Advanced SOC Analyst CLI Interface
Human-readable, context-aware interface designed for security operations
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.columns import Columns
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich import box
from typing import List, Dict, Any, Optional
import time
from datetime import datetime
from ..utils.threat_scoring import ThreatScorer
from .dashboard import ThreatIntelligenceDashboard


class SOCInterface:
    """Advanced CLI interface for SOC analysts"""

    def __init__(self):
        # Initialize console with proper encoding handling for Windows
        import sys
        import io

        # Ensure UTF-8 encoding on Windows
        if sys.platform == 'win32':
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except AttributeError:
                # Python < 3.7 fallback
                if hasattr(sys.stdout, 'buffer'):
                    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

        self.console = Console(record=True)
        self.session_start = datetime.now()
        self.dashboard = ThreatIntelligenceDashboard(self.console)
        
    def display_banner(self, available_sources: list = None):
        """Display SOC Forge banner with system info"""
        banner_text = """╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ███████╗ ██████╗  ██████╗    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗   ║
║   ██╔════╝██╔═══██╗██╔════╝    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝   ║
║   ███████╗██║   ██║██║         █████╗  ██║   ██║██████╔╝██║  ███╗█████╗     ║
║   ╚════██║██║   ██║██║         ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝     ║
║   ███████║╚██████╔╝╚██████╗    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗   ║
║   ╚══════╝ ╚═════╝  ╚═════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ║
║                                                                               ║
║                      ADVANCED IP THREAT INTELLIGENCE                          ║
║                                  v3.0                                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝"""

        self.console.print(banner_text, style="bold blue")
        self.console.print(f"Session Start: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}")

        if available_sources:
            sources_text = " | ".join([source.replace('_', '').title() for source in available_sources])
            self.console.print(f"Enabled Sources: {sources_text}")

        self.console.print("-------------------------------------------------------------------------------")

    def display_main_menu(self) -> str:
        """Display the main menu with core SOC operations"""
        menu_text = """
Available Operations:

  [1] Threat Scan
      • Perform single or bulk lookup across all configured intelligence feeds

  [2] Generate SIEM / Kibana Queries
      • Convert indicators into ready-to-use KQL / Lucene / EQL / Splunk syntax

  [3] API Configuration & Health Check
      • Validate API keys, check rate limits, and verify feed connectivity

  [4] Check Threat Feeds Status
      • Display available threat feeds and their statistics

  [5] Check DNS Blacklists (DNSBL)
      • Check IP reputation across 50+ DNS blacklist servers

  [6] List Available DNSBL Servers
      • Display all configured DNSBL servers and their details

  [7] Generate PDF Report
      • Create a professional threat intelligence report for analyzed IPs

  [8] Ransomware Intelligence
      • Search ransomware groups, victims, and check IOCs against ransomware.live

  [0] Exit

-------------------------------------------------------------------------------"""

        self.console.print(menu_text)
        return self.console.input("Select an option: ")

    def get_ip_input(self) -> str:
        """Get IP input from user with helpful guidance"""
        input_guidelines = """
INPUT GUIDELINES
  • Single IP:           8.8.8.8
  • Multiple (comma):    8.8.8.8, 1.1.1.1, 208.67.222.222
  • Line-separated:      One per line
  • With ports:          192.168.1.1:80, 10.0.0.1:443
  • With prefixes:       IP: 8.8.8.8, Address: 1.1.1.1

Press ENTER twice to submit, or Ctrl+C to cancel.
-------------------------------------------------------------------------------

Enter indicators:"""

        self.console.print(input_guidelines)

        lines = []
        try:
            while True:
                line = input(" ")
                if not line:
                    break
                lines.append(line)
        except (EOFError, KeyboardInterrupt):
            self.console.print("\n[yellow]Input cancelled[/yellow]")
            return ""

        return '\n'.join(lines)
    
    def display_parsing_results(self, parsing_result):
        """Display IP parsing results with detailed breakdown"""
        if not parsing_result.valid_ips:
            self.console.print("\n[red]No valid public IPs found for analysis[/red]")

            if parsing_result.private_ips_found:
                self.console.print(f"Private IPs found: {len(parsing_result.private_ips_found)}")
                for ip in parsing_result.private_ips_found[:5]:
                    self.console.print(f"  • {ip}")
                if len(parsing_result.private_ips_found) > 5:
                    self.console.print(f"  ... and {len(parsing_result.private_ips_found) - 5} more")

            return False

        # Success parsing results
        results_text = f"""
-------------------------------------------------------------------------------
INPUT PARSING RESULTS
-------------------------------------------------------------------------------
  Valid Public IPs   : {len(parsing_result.valid_ips)}
  Private IPs Found  : {len(parsing_result.private_ips_found)}
  Invalid Entries    : {len(parsing_result.invalid_entries)}
  Duplicates Removed : {parsing_result.duplicates_removed}

-------------------------------------------------------------------------------
TARGETS FOR ANALYSIS
-------------------------------------------------------------------------------"""

        self.console.print(results_text)

        # IP list
        for i, ip in enumerate(parsing_result.valid_ips, 1):
            self.console.print(f"  {i:<3} {ip:<15} Public")

        return True

    def generate_siem_queries(self) -> None:
        """Generate SIEM/Kibana queries for indicators"""
        self.console.print("\n")
        self.console.print("-------------------------------------------------------------------------------")
        self.console.print("SIEM / KIBANA QUERY GENERATION")
        self.console.print("-------------------------------------------------------------------------------")

        # Get indicators input
        indicators_input = self.get_ip_input()
        if not indicators_input.strip():
            return

        # Parse indicators (reuse IP parser for now)
        from ..core.ip_parser import IPParser
        parser = IPParser()
        parsing_result = parser.extract_ips(indicators_input, include_private=True)

        if not parsing_result.valid_ips and not parsing_result.private_ips_found:
            self.console.print("[red]No valid indicators found[/red]")
            return

        all_ips = parsing_result.valid_ips + parsing_result.private_ips_found

        # Generate different query types
        query_types = {
            "Elasticsearch/Kibana KQL": self._generate_kibana_kql,
            "Splunk SPL": self._generate_splunk_spl,
            "Microsoft Sentinel KQL": self._generate_sentinel_kql,
            "Elastic EQL": self._generate_elastic_eql,
            "Generic Lucene": self._generate_lucene_query
        }

        for query_name, generator_func in query_types.items():
            self.console.print(f"\n[bold cyan]{query_name}:[/bold cyan]")
            queries = generator_func(all_ips)
            for query_type, query in queries.items():
                self.console.print(f"\n[yellow]{query_type}:[/yellow]")
                self.console.print(f"[green]{query}[/green]")

    def _generate_kibana_kql(self, ips: list) -> dict:
        """Generate Kibana KQL queries"""
        ip_list = " OR ".join(ips)
        return {
            "Source IP Match": f"source.ip: ({ip_list})",
            "Destination IP Match": f"destination.ip: ({ip_list})",
            "Any IP Field": f"*.ip: ({ip_list})",
            "Network Traffic": f"(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND event.category: network"
        }

    def _generate_splunk_spl(self, ips: list) -> dict:
        """Generate Splunk SPL queries"""
        ip_list = " OR ".join([f'"{ip}"' for ip in ips])
        return {
            "Source IP Search": f'src_ip IN ({ip_list})',
            "Destination IP Search": f'dest_ip IN ({ip_list})',
            "Any IP Field": f'src_ip IN ({ip_list}) OR dest_ip IN ({ip_list}) OR ip IN ({ip_list})',
            "Stats by IP": f'src_ip IN ({ip_list}) OR dest_ip IN ({ip_list}) | stats count by src_ip, dest_ip'
        }

    def _generate_sentinel_kql(self, ips: list) -> dict:
        """Generate Microsoft Sentinel KQL queries"""
        ip_list = '","'.join(ips)
        return {
            "Network Connections": f'CommonSecurityLog | where SourceIP in ("{ip_list}") or DestinationIP in ("{ip_list}")',
            "DNS Queries": f'DnsEvents | where ClientIP in ("{ip_list}") or ServerIP in ("{ip_list}")',
            "Security Events": f'SecurityEvent | where IpAddress in ("{ip_list}") or WorkstationIP in ("{ip_list}")',
            "Firewall Logs": f'AzureDiagnostics | where SourceIP in ("{ip_list}") or TargetIP in ("{ip_list}")'
        }

    def _generate_elastic_eql(self, ips: list) -> dict:
        """Generate Elastic EQL queries"""
        ip_conditions = " or ".join([f'source.ip == "{ip}" or destination.ip == "{ip}"' for ip in ips])
        ip_list = '","'.join(ips)
        return {
            "Network Events": f'network where {ip_conditions}',
            "Process Events": f'process where source.ip in ("{ip_list}") or destination.ip in ("{ip_list}")' if ips else "",
            "Sequence Detection": f'sequence by source.ip [network where destination.ip in ("{ip_list}")] [process where true]' if ips else ""
        }

    def _generate_lucene_query(self, ips: list) -> dict:
        """Generate generic Lucene queries"""
        ip_list = " OR ".join(ips)
        return {
            "Basic IP Match": f"ip:({ip_list})",
            "Source IP": f"src_ip:({ip_list})",
            "Destination IP": f"dst_ip:({ip_list})",
            "Any IP Field": f"*ip*:({ip_list})"
        }

    def display_threat_feeds_status(self) -> None:
        """Display threat feeds status and statistics"""
        from ..feeds.threat_feed_manager import ThreatFeedManager

        self.console.print("\n")
        self.console.print("-------------------------------------------------------------------------------")
        self.console.print("THREAT FEEDS STATUS")
        self.console.print("-------------------------------------------------------------------------------")

        # Initialize threat feed manager
        self.console.print("\n[cyan]Initializing threat feed manager...[/cyan]")
        feed_manager = ThreatFeedManager()

        # Load feeds from cache or update them
        self.console.print("[cyan]Loading threat feeds (this may take a moment)...[/cyan]")
        update_results = feed_manager.update_feeds(force=False)

        successful_updates = sum(1 for v in update_results.values() if v)
        self.console.print(f"[green]Loaded {successful_updates}/{len(update_results)} feeds successfully[/green]\n")

        # Get feed stats
        stats = feed_manager.get_feed_stats()

        # Display summary
        summary_text = f"""
[bold]Overall Statistics:[/bold]
  Total Feeds Available  : {stats['total_feeds']}
  Feeds Loaded           : {stats['feeds_loaded']}
  Total Indicators       : {stats['total_indicators']:,}
  Feeds Needing Update   : {len(stats['needs_update'])}
"""
        self.console.print(summary_text)

        # Display feeds by category
        self.console.print("\n[bold]Feeds by Category:[/bold]")
        category_table = Table(box=box.SIMPLE, padding=(0, 1))
        category_table.add_column("Category", style="bold cyan", width=20)
        category_table.add_column("Feed Count", justify="center", width=15)

        for category, count in sorted(stats['by_category'].items()):
            category_table.add_row(category.title(), str(count))

        self.console.print(category_table)

        # Display feeds by type
        self.console.print("\n[bold]Feeds by Type:[/bold]")
        type_table = Table(box=box.SIMPLE, padding=(0, 1))
        type_table.add_column("Type", style="bold yellow", width=20)
        type_table.add_column("Feed Count", justify="center", width=15)

        for feed_type, count in sorted(stats['by_type'].items()):
            type_table.add_row(feed_type.upper(), str(count))

        self.console.print(type_table)

        # Display all feeds
        self.console.print("\n[bold]Available Threat Feeds:[/bold]")
        feeds_table = Table(box=box.SIMPLE, padding=(0, 1))
        feeds_table.add_column("Feed Name", style="bold white", width=35)
        feeds_table.add_column("Category", width=15)
        feeds_table.add_column("Type", width=10)
        feeds_table.add_column("Status", width=15)

        for feed in sorted(feed_manager.feeds.values(), key=lambda f: f.name):
            # Determine status
            if feed.indicators:
                status = f"[green]Loaded ({len(feed.indicators):,})[/green]"
            elif feed.needs_refresh():
                status = "[yellow]Needs Update[/yellow]"
            else:
                status = "[dim]Not Loaded[/dim]"

            feeds_table.add_row(
                feed.name,
                feed.category.title(),
                feed.feed_type.upper(),
                status
            )

        self.console.print(feeds_table)

        # Show feeds needing update
        if stats['needs_update']:
            self.console.print(f"\n[yellow]Note: {len(stats['needs_update'])} feeds need updating.[/yellow]")
            self.console.print("[dim]Feeds are automatically updated during threat scans.[/dim]")

    def display_api_health_check(self, analyzer) -> None:
        """Display API configuration and health check"""
        self.console.print("\n")
        self.console.print("-------------------------------------------------------------------------------")
        self.console.print("API CONFIGURATION & HEALTH CHECK")
        self.console.print("-------------------------------------------------------------------------------")

        if not analyzer:
            self.console.print("[red]No analyzer available[/red]")
            return

        # Check API status
        self.console.print("\nChecking APIs...")

        api_configs = {
            'virustotal': 'VirusTotal',
            'abuseipdb': 'AbuseIPDB',
            'ipinfo': 'IPInfo',
            'threatfox': 'ThreatFox',
            'greynoise': 'GreyNoise',
            'shodan': 'Shodan',
            'otx': 'AlienVault OTX',
            'ransomwarelive': 'RansomwareLive'
        }

        available_clients = analyzer.clients.keys()

        for api_key, api_name in api_configs.items():
            if api_key in available_clients:
                # Try to test the API
                try:
                    # Simple connectivity test - this would need to be implemented in each client
                    status = "[green]OK[/green]"
                except Exception:
                    status = "[red]ERROR[/red]"
            else:
                status = "[yellow]NOT CONFIGURED[/yellow]"

            self.console.print(f"  • {api_name:<15} {status}")

        # Display configuration summary
        self.console.print(f"\n[bold]Configuration Summary:[/bold]")
        self.console.print(f"  Active APIs: {len(available_clients)}/{len(api_configs)}")
        self.console.print(f"  Available Sources: {', '.join([name.title() for name in available_clients])}")

    def check_dnsbl(self) -> None:
        """Check IPs against DNS blacklists"""
        from ..feeds.dnsbl_checker import DNSBLChecker

        self.console.print("\n")
        self.console.print("-------------------------------------------------------------------------------")
        self.console.print("DNS BLACKLIST CHECK (DNSBL)")
        self.console.print("-------------------------------------------------------------------------------")

        # Get IP input
        ips_input = self.get_ip_input()
        if not ips_input.strip():
            return

        # Parse IPs
        from ..core.ip_parser import IPParser
        parser = IPParser()
        parsing_result = parser.extract_ips(ips_input, include_private=True)

        # Show parsing results
        if not self.display_parsing_results(parsing_result):
            return

        # Initialize DNSBL checker with animation
        dnsbl_checker = None
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Initializing DNSBL checker...", total=None)
            dnsbl_checker = DNSBLChecker(timeout=2.0, max_workers=10)
            progress.update(task, description=f"[green]✓ DNSBL checker initialized ({len(dnsbl_checker.DNSBL_SERVERS)} servers)")
            time.sleep(0.5)  # Brief pause to show completion

        # Check each IP
        for ip in parsing_result.valid_ips:
            self.console.print(f"\n[bold cyan]Checking {ip} against {len(dnsbl_checker.DNSBL_SERVERS)} DNSBL servers...[/bold cyan]")

            # Perform DNSBL check with progress animation
            dnsbl_results = None
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
                transient=False
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Querying DNSBL servers for {ip}...",
                    total=len(dnsbl_checker.DNSBL_SERVERS)
                )

                # Perform the check (this will happen in the background)
                dnsbl_results = dnsbl_checker.check_ip(ip)

                # Update progress to completion
                progress.update(task, completed=len(dnsbl_checker.DNSBL_SERVERS))
                progress.update(task, description=f"[green]✓ Scan complete - Checked {len(dnsbl_checker.DNSBL_SERVERS)} DNSBL servers")

            # Display results
            self._display_dnsbl_check_results(ip, dnsbl_results, dnsbl_checker.DNSBL_SERVERS)

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def display_dnsbl_list(self) -> None:
        """Display all available DNSBL servers"""
        from ..feeds.dnsbl_checker import DNSBLChecker

        self.console.print("\n")
        self.console.print("-------------------------------------------------------------------------------")
        self.console.print("AVAILABLE DNSBL SERVERS")
        self.console.print("-------------------------------------------------------------------------------")

        # Initialize DNSBL checker to get server list
        self.console.print("\n[cyan]Loading DNSBL server list...[/cyan]")
        dnsbl_checker = DNSBLChecker()

        # Get all DNSBL servers
        all_dnsbls = dnsbl_checker.DNSBL_SERVERS

        # Display summary
        summary_text = f"""
[bold]Overall Statistics:[/bold]
  Total DNSBL Servers    : {len(all_dnsbls)}
  Categories             : {len(set(d['category'] for d in all_dnsbls))}
"""
        self.console.print(summary_text)

        # Count by category
        from collections import defaultdict
        by_category = defaultdict(int)
        for dnsbl in all_dnsbls:
            by_category[dnsbl['category']] += 1

        # Display category breakdown
        self.console.print("\n[bold]DNSBLs by Category:[/bold]")
        category_table = Table(box=box.SIMPLE, padding=(0, 1))
        category_table.add_column("Category", style="bold cyan", width=20)
        category_table.add_column("Count", justify="center", width=10)

        for category in sorted(by_category.keys()):
            count = by_category[category]
            category_table.add_row(category.title(), str(count))

        self.console.print(category_table)

        # Display all DNSBL servers
        self.console.print("\n[bold]Complete DNSBL Server List:[/bold]")
        dnsbl_table = Table(box=box.SIMPLE, padding=(0, 1), show_header=True)
        dnsbl_table.add_column("Name", style="bold white", width=30)
        dnsbl_table.add_column("Server", style="cyan", width=35)
        dnsbl_table.add_column("Category", width=15)
        dnsbl_table.add_column("Description", width=40)

        # Group by category for better organization
        for category in sorted(by_category.keys()):
            # Add category header
            category_dnsbls = [d for d in all_dnsbls if d['category'] == category]

            for dnsbl in sorted(category_dnsbls, key=lambda x: x['name']):
                name = dnsbl['name']
                server = dnsbl['server']
                cat = dnsbl['category']
                description = dnsbl.get('description', '')[:40]

                # Color code categories
                if cat in ['spam', 'botnet', 'exploit', 'attack']:
                    cat_display = f"[red]{cat}[/red]"
                elif cat in ['proxy', 'policy']:
                    cat_display = f"[yellow]{cat}[/yellow]"
                elif cat == 'whitelist':
                    cat_display = f"[green]{cat}[/green]"
                else:
                    cat_display = cat

                dnsbl_table.add_row(name, server, cat_display, description)

        self.console.print(dnsbl_table)

        # Display additional info
        self.console.print(f"\n[bold cyan]Total DNSBL Servers Configured:[/bold cyan] {len(all_dnsbls)}")
        self.console.print("[dim]These servers are checked when performing DNSBL scans (Option 5)[/dim]")

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def generate_pdf_report(self, analyzer) -> None:
        """Generate comprehensive PDF report for analyzed IPs"""
        from ..reports.professional_report import ProfessionalThreatReport
        from ..feeds.dnsbl_checker import DNSBLChecker
        from ..feeds.threat_feed_manager import ThreatFeedManager

        self.console.print("\n")
        self.console.print("-------------------------------------------------------------------------------")
        self.console.print("GENERATE THREAT INTELLIGENCE PDF REPORT")
        self.console.print("-------------------------------------------------------------------------------")

        # Language selection
        self.console.print("\n[bold cyan]Select Report Language:[/bold cyan]")
        self.console.print("  [1] English (ENG)")
        self.console.print("  [2] Portuguese - Brazil (PT-BR)")
        self.console.print("  [3] French (FR)")

        lang_choice = self.console.input("\n[bold cyan]Choose language (1-3) [default: 1]:[/bold cyan] ").strip()

        language_map = {
            '1': 'ENG',
            '2': 'PT-BR',
            '3': 'FR',
            '': 'ENG'  # Default
        }

        language = language_map.get(lang_choice, 'ENG')
        lang_names = {'ENG': 'English', 'PT-BR': 'Portuguese (Brazil)', 'FR': 'French'}
        self.console.print(f"[green]✓ Selected language: {lang_names[language]}[/green]\n")

        # Get IP input
        ips_input = self.get_ip_input()
        if not ips_input.strip():
            return

        # Parse IPs
        from ..core.ip_parser import IPParser
        parser = IPParser()
        parsing_result = parser.extract_ips(ips_input, include_private=False)

        # Show parsing results
        if not self.display_parsing_results(parsing_result):
            return

        # Confirm generation
        if len(parsing_result.valid_ips) > 5:
            confirm = self.console.input(f"\n[yellow]Generate {len(parsing_result.valid_ips)} PDF reports? This may take a few minutes. (Y/n):[/yellow] ")
            if confirm.lower() in ['n', 'no']:
                return

        # Initialize components
        dnsbl_checker = DNSBLChecker(timeout=2.0, max_workers=10)
        feed_manager = ThreatFeedManager()

        # Process each IP
        generated_reports = []
        for idx, ip in enumerate(parsing_result.valid_ips, 1):
            self.console.print(f"\n[bold cyan]Processing {idx}/{len(parsing_result.valid_ips)}: {ip}[/bold cyan]")

            try:
                # Perform comprehensive analysis
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=self.console,
                    transient=True
                ) as progress:
                    # API analysis
                    task = progress.add_task(f"[cyan]Analyzing via threat intelligence APIs...", total=None)
                    analysis_result = analyzer.analyze_single_ip(ip, check_feeds=False)  # We'll check feeds separately
                    progress.update(task, description=f"[green]✓ API analysis complete")
                    time.sleep(0.3)

                    # DNSBL check
                    task2 = progress.add_task(f"[cyan]Checking DNS blacklists...", total=None)
                    dnsbl_results = dnsbl_checker.check_ip(ip)
                    progress.update(task2, description=f"[green]✓ DNSBL check complete")
                    time.sleep(0.3)

                    # Threat feeds
                    task3 = progress.add_task(f"[cyan]Checking threat intelligence feeds...", total=None)
                    feed_check_result = feed_manager.check_indicator(ip, feed_types=['IP'])
                    progress.update(task3, description=f"[green]✓ Threat feed check complete")
                    time.sleep(0.3)

                # Transform feed results for report
                feed_results = {
                    'found': len(feed_check_result.get('found_in', [])) > 0,
                    'feed_count': len(feed_check_result.get('found_in', [])),
                    'categories': feed_check_result.get('categories', []),
                    'threat_level': feed_check_result.get('threat_level', 'UNKNOWN'),
                    'feeds': []
                }

                # Get feed details for those that matched
                if feed_results['found']:
                    for feed_name in feed_check_result.get('found_in', []):
                        if feed_name in feed_manager.feeds:
                            feed = feed_manager.feeds[feed_name]
                            feed_results['feeds'].append({
                                'name': feed.name,
                                'category': feed.category,
                                'type': feed.feed_type,
                                'description': feed.description
                            })

                # Combine all data
                complete_analysis = {
                    **analysis_result.data,
                    'dnsbl': dnsbl_results,
                    'threat_feeds': feed_results
                }

                # Generate PDF
                self.console.print(f"[cyan]Generating professional PDF report in {lang_names[language]}...[/cyan]")
                pdf_report = ProfessionalThreatReport(language=language)
                pdf_path = pdf_report.generate_report(ip, complete_analysis)

                generated_reports.append((ip, pdf_path))
                self.console.print(f"[green]✓ Report generated:[/green] {pdf_path}")

            except Exception as e:
                self.console.print(f"[red]✗ Error generating report for {ip}: {str(e)}[/red]")
                continue

        # Summary
        if generated_reports:
            self.console.print("\n[bold green]PDF Report Generation Complete![/bold green]")
            self.console.print(f"\n[bold]Generated {len(generated_reports)} report(s):[/bold]")
            for ip, path in generated_reports:
                self.console.print(f"  • {ip}: {path}")
            self.console.print(f"\n[dim]Reports saved to: outputs/reports/[/dim]")
        else:
            self.console.print("\n[yellow]No reports were generated.[/yellow]")

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _display_dnsbl_check_results(self, ip: str, dnsbl_results: dict, all_dnsbls: list) -> None:
        """Display DNSBL check results for a single IP"""
        listing_count = dnsbl_results.get('total_listings', 0)
        threat_level = dnsbl_results.get('threat_level', 'UNKNOWN')
        is_whitelisted = dnsbl_results.get('is_whitelisted', False)
        total_checked = dnsbl_results.get('total_checked', 0)
        listings = dnsbl_results.get('listed_in', [])
        categories = dnsbl_results.get('categories', [])

        # Create a set of DNSBLs where IP was found
        listed_dnsbl_names = {listing.get('name') for listing in listings}

        # Create header panel
        header = Panel(
            f"[bold white]DNSBL Results for {ip}[/bold white]",
            style="bold magenta",
            box=box.DOUBLE
        )
        self.console.print(header)

        # Handle error case
        if dnsbl_results.get('error'):
            self.console.print(f"[red]Error: {dnsbl_results['error']}[/red]")
            return

        # Separate whitelist and blacklist entries
        blacklist_entries = [l for l in listings if l.get('category') != 'whitelist']
        whitelist_entries = [l for l in listings if l.get('category') == 'whitelist']
        blacklist_count = len(blacklist_entries)
        blacklist_categories = [c for c in categories if c != 'whitelist']

        # Show whitelist information if present
        if is_whitelisted and whitelist_entries:
            whitelist_names = [w.get('name', 'Unknown') for w in whitelist_entries]
            self.console.print(f"[bold cyan]ℹ️  IP found in whitelist(s):[/bold cyan] {', '.join(whitelist_names)}")

            # If ONLY in whitelist and no blacklists
            if blacklist_count == 0:
                self.console.print(f"[bold green]✓ IP is whitelisted and NOT listed in any blacklists[/bold green]")
                self.console.print(f"[dim]Checked {total_checked} DNSBL servers[/dim]")
                # Continue to show full table
            else:
                # In both whitelist AND blacklists
                self.console.print(f"[bold yellow]⚠️  Warning: IP is whitelisted BUT also found in {blacklist_count} blacklist(s)[/bold yellow]")
                self.console.print(f"[dim]This may indicate a compromised trusted host or false positive[/dim]\n")

        # Color code threat level
        if threat_level == "CRITICAL":
            level_color = "bold red"
        elif threat_level == "HIGH":
            level_color = "red"
        elif threat_level == "MEDIUM":
            level_color = "yellow"
        elif listing_count == 0:
            level_color = "bold green"
        else:
            level_color = "green"

        # Display summary based on status
        if listing_count == 0:
            summary = f"""
[bold green]✓ IP CLEAN - Not listed in any DNS blacklists[/bold green]

[bold white]Threat Level:[/bold white] [{level_color}]{threat_level}[/{level_color}]
[bold white]Results:[/bold white] 0 listings out of {total_checked} DNSBLs checked
"""
        else:
            summary = f"""
[bold red]⚠ IP LISTED IN DNS BLACKLISTS ⚠[/bold red]

[bold white]Threat Level:[/bold white] [{level_color}]{threat_level}[/{level_color}]
[bold white]Listings:[/bold white] {blacklist_count} out of {total_checked} DNSBLs
[bold white]Categories:[/bold white] {', '.join(blacklist_categories) if blacklist_categories else 'Unknown'}
"""
        self.console.print(summary)

        # Display complete DNSBL table with all results
        self.console.print("\n[bold]Complete DNSBL Scan Results:[/bold]")

        dnsbl_table = Table(box=box.SIMPLE, padding=(0, 1), show_header=True)
        dnsbl_table.add_column("DNSBL", style="bold white", width=28)
        dnsbl_table.add_column("Category", width=12)
        dnsbl_table.add_column("Status", width=15)
        dnsbl_table.add_column("Description", width=35)

        # First, add all blacklist entries
        for listing in blacklist_entries:
            name = listing.get('name', 'Unknown')
            category = listing.get('category', 'unknown')
            result = listing.get('result', 'listed')
            description = listing.get('description', '')[:35]

            # Color code category and status
            if category in ['spam', 'botnet', 'exploit', 'attack']:
                category_display = f"[red]{category}[/red]"
                status_display = f"[red]LISTED[/red]"
            elif category in ['proxy', 'policy']:
                category_display = f"[yellow]{category}[/yellow]"
                status_display = f"[yellow]LISTED[/yellow]"
            else:
                category_display = category
                status_display = f"[red]LISTED[/red]"

            dnsbl_table.add_row(name, category_display, status_display, description)

        # Then add all DNSBLs that didn't list the IP
        for dnsbl in all_dnsbls:
            if dnsbl['name'] not in listed_dnsbl_names:
                name = dnsbl['name']
                category = dnsbl['category']
                description = dnsbl.get('description', '')[:35]

                # Gray out clean entries
                category_display = f"[dim]{category}[/dim]"
                status_display = "[green]Clean[/green]"

                dnsbl_table.add_row(name, category_display, status_display, description)

        self.console.print(dnsbl_table)

        # Display count summary
        clean_count = total_checked - blacklist_count
        self.console.print(f"\n[bold]Summary:[/bold]")
        if blacklist_count > 0:
            self.console.print(f"  [red]• Listed:[/red] {blacklist_count} DNSBL(s)")
        self.console.print(f"  [green]• Clean:[/green] {clean_count} DNSBL(s)")
        self.console.print(f"  [cyan]• Total Checked:[/cyan] {total_checked} DNSBL(s)")

    def run_dashboard_analysis(self, ips: list, analyzer) -> None:
        """Run comprehensive analysis and display dashboard directly"""
        import logging
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

        available_sources = list(analyzer.clients.keys())

        # Temporarily suppress logging to console during analysis
        feed_logger = logging.getLogger('soc_forge.feeds.threat_feed_manager')
        analyzer_logger = logging.getLogger('soc_forge.analyzer')

        # Store original levels
        original_feed_level = feed_logger.level
        original_analyzer_level = analyzer_logger.level

        # Set to ERROR to suppress INFO/WARNING
        feed_logger.setLevel(logging.ERROR)
        analyzer_logger.setLevel(logging.ERROR)

        # Map sources to display names
        source_display = {
            'virustotal': '🛡️  VirusTotal',
            'abuseipdb': '🚫 AbuseIPDB',
            'shodan': '🔍 Shodan',
            'otx': '👁️  AlienVault OTX',
            'greynoise': '📡 GreyNoise',
            'ipinfo': '🌍 IPInfo',
            'threatfox': '🦊 ThreatFox'
        }

        # Create API progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            TaskProgressColumn(),
            console=self.console,
            transient=True
        ) as progress:

            # Task 1: API Analysis
            api_task = progress.add_task(
                f"[cyan]Querying threat intelligence APIs...",
                total=len(ips) * len(available_sources)
            )

            # Simulate API progress with source names (slower)
            for ip in ips:
                for source in available_sources:
                    display_name = source_display.get(source, source.upper())
                    progress.update(api_task, advance=1, description=f"[cyan]🔄 {display_name}")
                    time.sleep(0.35)  # Slower for better visibility

            # Mark as complete
            progress.update(api_task, completed=len(ips) * len(available_sources), description="[green]✓ API queries complete")
            time.sleep(0.3)

        self.console.print("[bold green]✓ API queries complete![/bold green]\n")

        # Simple threat feeds progress display
        if hasattr(analyzer, 'feed_manager') and analyzer.feed_manager:
            feed_count = [0]
            total_iocs = [0]

            # Category color mapping
            category_colors = {
                'malware': 'red',
                'botnet': 'red',
                'c2': 'orange1',
                'phishing': 'yellow',
                'spam': 'yellow',
                'exploit': 'red',
                'attack': 'red',
                'proxy': 'cyan',
                'general': 'blue',
                'reputation': 'magenta'
            }

            def feed_callback(feed_name, ioc_count, category='general'):
                feed_count[0] += 1
                total_iocs[0] += ioc_count

                # Get category color
                cat_color = category_colors.get(category, 'blue')
                category_tag = f"[{cat_color}]{category}[/{cat_color}]"

                # Print feed with category tag on the right
                ioc_text = f"({ioc_count:,} IOCs)"
                # Calculate padding to align categories on the right
                name_and_ioc = f"  [dim]→[/dim] [magenta]{feed_name}[/magenta] [dim]{ioc_text}[/dim]"
                padding = max(0, 70 - len(feed_name) - len(ioc_text))

                self.console.print(f"{name_and_ioc}{' ' * padding}[{cat_color}]#{category}[/{cat_color}]")

            analyzer.feed_manager.progress_callback = feed_callback
            self.console.print("[bold magenta]📋 Loading Threat Feeds...[/bold magenta]")

        # Run actual analysis
        results = analyzer.analyze_multiple_ips(ips)

        # Show completion
        if hasattr(analyzer, 'feed_manager') and analyzer.feed_manager:
            self.console.print(f"\n[bold green]✓ Loaded {feed_count[0]} threat feeds with {total_iocs[0]:,} total IOCs![/bold green]\n")

        # Restore original log levels
        feed_logger.setLevel(original_feed_level)
        analyzer_logger.setLevel(original_analyzer_level)

        self.console.print("[bold green]✓ Analysis complete![/bold green]\n")

        # Display full dashboard for each IP
        for ip in ips:
            if ip in results:
                self.display_threat_intelligence_dashboard(ip, results[ip].data)
    
    def display_analysis_progress(self, ips: List[str], sources: List[str]):
        """Display real-time analysis progress with animations"""
        from rich.live import Live
        from rich.table import Table
        from rich.panel import Panel
        from rich.align import Align

        # Map sources to display names with emojis
        source_display = {
            'virustotal': '🛡️  VirusTotal',
            'abuseipdb': '🚫 AbuseIPDB',
            'shodan': '🔍 Shodan',
            'otx': '👁️  AlienVault OTX',
            'greynoise': '📡 GreyNoise',
            'ipinfo': '🌍 IPInfo',
            'threatfox': '🦊 ThreatFox',
            'threat_feeds': '📋 Threat Feeds',
            'dnsbl': '🔍 DNSBL'
        }

        # Create status tracking
        source_status = {source: 'pending' for source in sources}

        # Spinner frames for custom animation
        spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        current_frame = 0

        def create_progress_display():
            nonlocal current_frame

            # Create header with animated spinner
            spinner_char = spinner_frames[current_frame % len(spinner_frames)]
            header = Text(f"{spinner_char} Collecting Threat Intelligence...", style="bold cyan")

            # Create progress table
            table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), border_style="dim")
            table.add_column("Source", style="bold white", width=30)
            table.add_column("Status", width=25, justify="left")

            for source in sources:
                display_name = source_display.get(source, source.upper())
                status = source_status[source]

                if status == 'pending':
                    status_text = "[dim]⏳ Waiting...[/dim]"
                elif status == 'running':
                    status_text = f"[yellow]{spinner_char} Querying...[/yellow]"
                elif status == 'complete':
                    status_text = "[green]✓ Complete[/green]"
                elif status == 'error':
                    status_text = "[red]✗ Failed[/red]"
                else:
                    status_text = "[dim]...[/dim]"

                table.add_row(display_name, status_text)

            from rich.console import Group
            content = Group(
                Align.center(header),
                Text(""),
                table
            )

            return Panel(
                content,
                title="[bold yellow]⚡ Analysis in Progress[/bold yellow]",
                border_style="yellow",
                box=box.HEAVY,
                padding=(1, 2)
            )

        # Run progress with live updates (slower animation, transient so it disappears)
        with Live(create_progress_display(), console=self.console, refresh_per_second=4, transient=True) as live:
            for ip in ips:
                for source in sources:
                    # Update status to running
                    source_status[source] = 'running'
                    current_frame += 1
                    live.update(create_progress_display())
                    time.sleep(0.4)  # Slower animation

                    # Update status to complete
                    source_status[source] = 'complete'
                    current_frame += 1
                    live.update(create_progress_display())
                    time.sleep(0.2)  # Slower animation

            # Final update
            time.sleep(0.5)

        # Show completion message
        self.console.print("\n[bold green]✓ Threat intelligence collection complete![/bold green]\n")

    def create_feed_progress_callback(self):
        """Create a callback function for threat feed loading with live display"""
        from rich.live import Live
        from rich.table import Table
        from rich.panel import Panel
        from rich.align import Align
        import threading

        spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        loaded_feeds = {}
        live_display = None
        frame_counter = [0]
        lock = threading.Lock()

        def create_feed_display():
            # Animated spinner
            spinner_char = spinner_frames[frame_counter[0] % len(spinner_frames)]
            header = Text(f"{spinner_char} Loading Threat Intelligence Feeds...", style="bold magenta")

            # Create table for loaded feeds
            table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1), border_style="dim")
            table.add_column("Feed", style="bold white", width=45)
            table.add_column("IOCs", width=12, justify="right")
            table.add_column("", width=10)

            for feed_name, ioc_count in loaded_feeds.items():
                ioc_text = f"[cyan]{ioc_count:,}[/cyan]" if ioc_count > 0 else "[dim]0[/dim]"
                table.add_row(feed_name, ioc_text, "[green]✓[/green]")

            from rich.console import Group
            content = Group(
                Align.center(header),
                Text(""),
                table if loaded_feeds else Text("[dim]Initializing...[/dim]", style="dim", justify="center")
            )

            return Panel(
                content,
                title="[bold cyan]📋 Threat Feed Manager[/bold cyan]",
                border_style="cyan",
                box=box.HEAVY,
                padding=(1, 2)
            )

        def feed_callback(feed_name, ioc_count):
            with lock:
                loaded_feeds[feed_name] = ioc_count
                frame_counter[0] += 1
                if live_display:
                    live_display.update(create_feed_display())

        def start_display():
            nonlocal live_display
            live_display = Live(create_feed_display(), console=self.console, refresh_per_second=4, transient=False)
            live_display.start()
            return live_display

        def stop_display():
            if live_display:
                live_display.stop()
                self.console.print("[bold green]✓ Threat feeds loaded successfully![/bold green]\n")

        return feed_callback, start_display, stop_display

    def display_threat_summary(self, results):
        """Display high-level threat assessment summary"""
        total_ips = len(results)
        malicious_count = 0
        suspicious_count = 0
        clean_count = 0
        
        threat_levels = {}
        
        for ip, result in results.items():
            # Handle both AnalysisResult objects and plain dictionaries
            data = result.data if hasattr(result, 'data') else result
            threat_score = ThreatScorer.calculate_ip_threat_score(data)

            if threat_score >= 70:
                malicious_count += 1
                threat_levels[ip] = ("HIGH RISK", "red")
            elif threat_score >= 30:
                suspicious_count += 1
                threat_levels[ip] = ("SUSPICIOUS", "yellow")
            else:
                clean_count += 1
                threat_levels[ip] = ("CLEAN", "green")
        
        # Summary statistics
        summary_table = Table(title="Threat Assessment Summary", box=box.SIMPLE, border_style="red")
        summary_table.add_column("Risk Level", style="bold")
        summary_table.add_column("Count", justify="center")
        summary_table.add_column("Percentage", justify="center")
        
        summary_table.add_row("HIGH RISK", str(malicious_count), f"{(malicious_count/total_ips)*100:.1f}%")
        summary_table.add_row("SUSPICIOUS", str(suspicious_count), f"{(suspicious_count/total_ips)*100:.1f}%")
        summary_table.add_row("CLEAN", str(clean_count), f"{(clean_count/total_ips)*100:.1f}%")
        
        # Individual IP results
        ip_results_table = Table(title="Individual IP Assessment", box=box.SIMPLE, border_style="blue")
        ip_results_table.add_column("IP Address", style="bold white")
        ip_results_table.add_column("Risk", justify="center")
        ip_results_table.add_column("Status", style="bold")
        ip_results_table.add_column("Key Findings", style="dim")
        
        for ip, (level, color) in threat_levels.items():
            # Handle both AnalysisResult objects and plain dictionaries
            result = results[ip]
            data = result.data if hasattr(result, 'data') else result
            findings = ThreatScorer.extract_key_findings(data)
            
            # Create risk icon based on level
            if level == "HIGH RISK":
                icon = "!!!"
            elif level == "SUSPICIOUS":
                icon = "!?"
            else:
                icon = "OK"
                
            ip_results_table.add_row(ip, icon, f"[{color}]{level}[/{color}]", findings)
        
        self.console.print(summary_table)
        self.console.print(ip_results_table)
    
    def display_detailed_analysis(self, ip: str, results: Dict[str, Any]):
        """Display detailed analysis for a single IP"""
        # Header
        threat_score = ThreatScorer.calculate_ip_threat_score(results)
        risk_level = ThreatScorer.get_threat_level(threat_score)
        risk_color = ThreatScorer.get_threat_color(threat_score)
        
        header_panel = Panel(
            f"[bold white]{ip}[/bold white]\n[{risk_color}]{risk_level}[/{risk_color}] (Threat Score: {threat_score}/100)",
            title=f"Detailed Analysis",
            border_style=risk_color
        )
        self.console.print(header_panel)
        
        # Create multi-column layout for different data sources
        columns = []
        
        # VirusTotal results
        if 'virustotal' in results:
            vt_data = results['virustotal']
            if vt_data.get('found'):
                vt_content = self._format_virustotal_results(vt_data)
                columns.append(Panel(vt_content, title="VirusTotal", border_style="purple"))

                # Show detailed vendor breakdown if there are detections
                if vt_data.get('engines_detected'):
                    self.console.print()
                    self.display_virustotal_vendor_breakdown(ip, vt_data)
        
        # AbuseIPDB results  
        if 'abuseipdb' in results:
            abuse_data = results['abuseipdb']
            if abuse_data.get('found'):
                abuse_content = self._format_abuseipdb_results(abuse_data)
                columns.append(Panel(abuse_content, title="AbuseIPDB", border_style="red"))
        
        # GreyNoise results
        if 'greynoise' in results:
            gn_data = results['greynoise']
            if gn_data.get('found'):
                gn_content = self._format_greynoise_results(gn_data)
                columns.append(Panel(gn_content, title="GreyNoise", border_style="blue"))
        
        # ThreatFox results
        if 'threatfox' in results:
            tf_data = results['threatfox']
            if tf_data.get('found'):
                tf_content = self._format_threatfox_results(tf_data)
                columns.append(Panel(tf_content, title="ThreatFox", border_style="orange1"))
        
        # IPInfo results
        if 'ipinfo' in results:
            ip_data = results['ipinfo']
            if ip_data.get('found'):
                ip_content = self._format_ipinfo_results(ip_data)
                columns.append(Panel(ip_content, title="IPInfo", border_style="green"))

        # Shodan results
        if 'shodan' in results:
            shodan_data = results['shodan']
            if shodan_data.get('found'):
                shodan_content = self._format_shodan_results(shodan_data)
                columns.append(Panel(shodan_content, title="Shodan", border_style="cyan"))

        if columns:
            self.console.print(Columns(columns, equal=True))
        else:
            self.console.print("[dim]No detailed results available[/dim]")
    
    
    def _format_virustotal_results(self, data: Dict[str, Any]) -> str:
        """Format VirusTotal results for display"""
        content = []

        # Detection summary
        ratio = data.get('vendor_detection_ratio', '0/0')
        content.append(f"[bold red]Detection Ratio:[/bold red] {ratio}")
        content.append(f"[red]Malicious:[/red] {data.get('malicious', 0)}")
        content.append(f"[yellow]Suspicious:[/yellow] {data.get('suspicious', 0)}")
        content.append(f"[green]Harmless:[/green] {data.get('harmless', 0)}")

        if data.get('reputation'):
            content.append(f"[blue]Reputation:[/blue] {data['reputation']}")

        # Show top detecting engines
        engines_detected = data.get('engines_detected', [])
        if engines_detected:
            content.append(f"\n[bold]Top Detections:[/bold]")
            for i, engine in enumerate(engines_detected[:5]):  # Show top 5
                result = engine.get('result', 'N/A')
                category = engine.get('category', 'unknown')
                color = "red" if category == "malicious" else "yellow"
                content.append(f"[{color}]• {engine['engine']}:[/{color}] {result}")

        if data.get('malware_families'):
            content.append(f"\n[purple]Malware Families:[/purple] {', '.join(data['malware_families'][:3])}")

        return "\n".join(content)

    def display_virustotal_vendor_breakdown(self, ip: str, vt_data: Dict[str, Any]):
        """Display detailed VirusTotal vendor breakdown in a table"""
        if not vt_data.get('engines_detected'):
            return

        # Create detailed vendor table
        vendor_table = Table(title=f"VirusTotal Vendor Detections - {ip}",
                           box=box.SIMPLE, border_style="red")
        vendor_table.add_column("Engine", style="bold white", width=20)
        vendor_table.add_column("Result", style="red", width=30)
        vendor_table.add_column("Category", justify="center", width=12)
        vendor_table.add_column("Method", style="dim", width=15)

        for engine in vt_data['engines_detected']:
            category = engine.get('category', 'unknown')
            category_color = "red" if category == "malicious" else "yellow"

            vendor_table.add_row(
                engine.get('engine', 'Unknown'),
                engine.get('result', 'N/A'),
                f"[{category_color}]{category.upper()}[/{category_color}]",
                engine.get('method', 'N/A')
            )

        self.console.print(vendor_table)

        # Additional statistics
        stats_panel = Panel(
            f"[bold]Detection Statistics:[/bold]\n"
            f"Detection Ratio: [red]{vt_data.get('vendor_detection_ratio', '0/0')}[/red]\n"
            f"Reputation Score: [blue]{vt_data.get('reputation', 'N/A')}[/blue]\n"
            f"Last Analysis: [dim]{vt_data.get('last_analysis_date', 'N/A')}[/dim]",
            title="VirusTotal Summary",
            border_style="purple"
        )
        self.console.print(stats_panel)

    def _format_abuseipdb_results(self, data: Dict[str, Any]) -> str:
        """Format AbuseIPDB results for display"""
        content = []
        content.append(f"[red]Confidence:[/red] {data.get('confidence_score', 0)}%")
        content.append(f"[yellow]Reports:[/yellow] {data.get('total_reports', 0)}")
        
        if data.get('country_name'):
            content.append(f"[blue]Country:[/blue] {data['country_name']}")
        
        if data.get('isp'):
            content.append(f"[green]ISP:[/green] {data['isp'][:20]}...")
        
        if data.get('last_reported'):
            content.append(f"[dim]Last Report:[/dim] {data['last_reported'][:10]}")
        
        return "\n".join(content)
    
    def _format_greynoise_results(self, data: Dict[str, Any]) -> str:
        """Format GreyNoise results for display"""
        content = []
        
        classification = data.get('classification', 'unknown')
        if classification == 'malicious':
            content.append(f"[red]Status:[/red] {classification.upper()}")
        elif classification == 'benign':
            content.append(f"[green]Status:[/green] {classification.upper()}")
        else:
            content.append(f"[yellow]Status:[/yellow] {classification.upper()}")
        
        if data.get('actor'):
            content.append(f"[purple]Actor:[/purple] {data['actor']}")
        
        if data.get('tags'):
            content.append(f"[blue]Tags:[/blue] {', '.join(data['tags'][:2])}")
        
        if data.get('first_seen'):
            content.append(f"[dim]First Seen:[/dim] {data['first_seen'][:10]}")
        
        return "\n".join(content)
    
    def _format_threatfox_results(self, data: Dict[str, Any]) -> str:
        """Format ThreatFox results for display"""
        content = []
        content.append(f"[red]IOCs Found:[/red] {data.get('ioc_count', 0)}")
        
        if data.get('malware_families'):
            content.append(f"[purple]Malware:[/purple] {', '.join(data['malware_families'][:2])}")
        
        if data.get('threat_types'):
            content.append(f"[yellow]Threats:[/yellow] {', '.join(data['threat_types'][:2])}")
        
        if data.get('confidence_level'):
            content.append(f"[blue]Confidence:[/blue] {data['confidence_level']:.1f}%")
        
        return "\n".join(content)
    
    def _format_ipinfo_results(self, data: Dict[str, Any]) -> str:
        """Format IPInfo results for display"""
        content = []
        
        if data.get('country'):
            location = f"{data.get('city', 'Unknown')}, {data['country']}"
            content.append(f"[blue]Location:[/blue] {location}")
        
        if data.get('asn_name'):
            content.append(f"[green]ASN:[/green] {data['asn_name'][:25]}...")
        
        if data.get('organization'):
            content.append(f"[yellow]Org:[/yellow] {data['organization'][:25]}...")
        
        if data.get('privacy_vpn'):
            content.append(f"[red]VPN/Proxy:[/red] Detected")

        return "\n".join(content)

    def _format_shodan_results(self, data: Dict[str, Any]) -> str:
        """Format Shodan results for display"""
        content = []

        # Basic info
        services_count = len(data.get('services', []))
        content.append(f"[blue]Open Ports:[/blue] {len(data.get('ports', []))}")
        content.append(f"[green]Services:[/green] {services_count}")

        # Vulnerabilities
        vuln_count = len(data.get('vulnerabilities', []))
        if vuln_count > 0:
            content.append(f"[red]Vulnerabilities:[/red] {vuln_count}")

        # Operating system
        if data.get('operating_system'):
            content.append(f"[yellow]OS:[/yellow] {data['operating_system']}")

        # Organization
        if data.get('organization'):
            org = data['organization'][:25] + "..." if len(data.get('organization', '')) > 25 else data['organization']
            content.append(f"[cyan]Org:[/cyan] {org}")

        # Top services
        services = data.get('services', [])
        if services:
            content.append(f"\n[bold]Top Services:[/bold]")
            for service in services[:3]:  # Show top 3
                port = service.get('port', '')
                product = service.get('product', 'Unknown')[:20]
                content.append(f"[dim]• Port {port}:[/dim] {product}")

        # Hostnames
        hostnames = data.get('hostnames', [])
        if hostnames:
            hostname_list = ', '.join(hostnames[:2])
            content.append(f"\n[purple]Hostnames:[/purple] {hostname_list}")

        # Tags
        tags = data.get('tags', [])
        if tags:
            tag_list = ', '.join(tags[:3])
            content.append(f"\n[orange1]Tags:[/orange1] {tag_list}")

        return "\n".join(content)

    def display_threat_intelligence_dashboard(self, ip: str, analysis_results: Dict[str, Any]) -> None:
        """Display the comprehensive threat intelligence dashboard"""
        self.dashboard.display_threat_intelligence_dashboard(ip, analysis_results)

    def display_quick_threat_dashboard(self, ip: str, quick_results: Dict[str, Any]) -> None:
        """Display the quick threat assessment dashboard"""
        self.dashboard.display_quick_dashboard(ip, quick_results)

    def ransomware_intelligence_menu(self, analyzer) -> None:
        """Ransomware intelligence operations menu"""
        from ..apis.ransomwarelive import RansomwareLiveClient

        self.console.print("\n")
        self.console.print("-------------------------------------------------------------------------------")
        self.console.print("RANSOMWARE INTELLIGENCE (ransomware.live)")
        self.console.print("-------------------------------------------------------------------------------")

        # Check if ransomware client is available
        if 'ransomwarelive' not in analyzer.clients:
            self.console.print("[red]Ransomware.live client not initialized[/red]")
            return

        ransomware_client = analyzer.clients['ransomwarelive']

        # Check if PRO API is enabled
        is_pro = ransomware_client.use_pro
        pro_badge = "[bold green][PRO][/bold green]" if is_pro else "[dim][PRO][/dim]"

        # Quick data availability check
        self.console.print("\n[dim]Checking data availability...[/dim]")

        data_status = {}
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                     console=self.console, transient=True) as progress:
            task = progress.add_task("[cyan]Testing endpoints...", total=None)

            # Check victims
            victims_test = ransomware_client.get_recent_victims()
            data_status['victims'] = victims_test.success and len(victims_test.data.get('victims', [])) > 0

            # Check groups
            groups_test = ransomware_client.get_groups()
            data_status['groups'] = groups_test.success and len(groups_test.data.get('groups', [])) > 0

            # Check PRO features if enabled
            if is_pro:
                stats_test = ransomware_client.get_statistics()
                data_status['stats'] = stats_test.success and bool(stats_test.data.get('statistics'))

            progress.update(task, description="[green]✓ Check complete")
            time.sleep(0.2)

        # Build status indicators
        victim_badge = "[green]●[/green]" if data_status.get('victims') else "[red]○[/red]"
        group_badge = "[green]●[/green]" if data_status.get('groups') else "[red]○[/red]"
        stats_badge = "[green]●[/green]" if data_status.get('stats') else "[red]○[/red]"

        menu_text = f"""
Available Operations:

  [bold cyan]THREAT INTELLIGENCE[/bold cyan]
  {victim_badge} [1] Check IOC Against Ransomware Activity
      • Search if an IP, domain, hash is associated with ransomware groups

  {victim_badge} [2] Search Ransomware Victims
      • Search for victims by keyword, organization, or domain name

  {victim_badge} [3] Get Recent Ransomware Activity
      • View recently disclosed victims and cyberattacks

  [bold cyan]GROUP INTELLIGENCE[/bold cyan]
  {group_badge} [4] List All Ransomware Groups
      • View all known active ransomware groups

  {group_badge} [5] Group Intelligence & Details
      • Get victims, YARA rules, and detailed info about a specific group

  [bold cyan]ANALYTICS & REPORTS[/bold cyan]
  {pro_badge} {stats_badge} [6] Statistics & Analytics
      • View ransomware activity statistics and trends

  [0] Back to Main Menu

{f"[bold green]✓ API PRO Enabled[/bold green] - 3000 calls/day" if is_pro else "[yellow]! Using Free API[/yellow] - Upgrade to PRO for advanced features"}
[dim]Legend: [green]●[/green] Data Available  [red]○[/red] No Data  •  Full IOC data: https://www.ransomware.live/groups/[groupname][/dim]
-------------------------------------------------------------------------------"""

        self.console.print(menu_text)
        choice = self.console.input("Select an option: ").strip()

        if choice == '1':
            self._check_ioc_ransomware(ransomware_client)
        elif choice == '2':
            self._search_victims(ransomware_client)
        elif choice == '3':
            self._get_recent_activity(ransomware_client)
        elif choice == '4':
            self._search_ransomware_groups(ransomware_client)
        elif choice == '5':
            self._get_group_intelligence(ransomware_client)
        elif choice == '6':
            self._view_statistics(ransomware_client)
        elif choice == '0':
            return
        else:
            self.console.print("[yellow]Invalid option[/yellow]")

    def _check_ioc_ransomware(self, client: 'RansomwareLiveClient') -> None:
        """Check if an IOC is associated with ransomware activity"""
        self.console.print("\n[bold cyan]Check IOC Against Ransomware Activity[/bold cyan]\n")

        # Show available data sources
        self.console.print("[dim]Searching across:[/dim]")
        self.console.print("[dim]  ✓ Victim database[/dim]")
        self.console.print("[dim]  ✓ IOC database (if available)[/dim]")
        self.console.print("[dim]  ✓ Cyberattack records[/dim]\n")

        ioc = self.console.input("Enter IOC (IP, domain, hash, keyword): ").strip()
        if not ioc:
            return

        self.console.print(f"\n[cyan]Searching ransomware.live for: {ioc}[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Querying ransomware.live...", total=None)
            result = client.check_ioc(ioc)
            progress.update(task, description="[green]✓ Query complete")
            time.sleep(0.3)

        if not result.success:
            self.console.print(f"[red]Error: {result.error}[/red]")
            return

        data = result.data

        # Create results panel
        if data.get('found'):
            threat_level = data.get('threat_level', 'UNKNOWN')
            level_color = {
                'CRITICAL': 'red',
                'HIGH': 'red',
                'MEDIUM': 'yellow',
                'LOW': 'green',
                'CLEAN': 'green'
            }.get(threat_level, 'yellow')

            summary = f"""
[bold {level_color}]⚠ IOC FOUND IN RANSOMWARE ACTIVITY ⚠[/bold {level_color}]

[bold white]IOC:[/bold white] {ioc}
[bold white]Threat Level:[/bold white] [{level_color}]{threat_level}[/{level_color}]
[bold white]Total Matches:[/bold white] {data.get('total_matches', 0)}
[bold white]Associated Groups:[/bold white] {', '.join(data.get('associated_groups', [])) or 'None'}
"""
            self.console.print(Panel(summary, border_style=level_color, title="Ransomware IOC Analysis"))

            # Display victims
            victims = data.get('victims', [])
            if victims:
                self.console.print(f"\n[bold]Victims Found ({len(victims)}):[/bold]")
                victim_table = Table(box=box.SIMPLE, padding=(0, 1))
                victim_table.add_column("Organization", style="bold white", width=40)
                victim_table.add_column("Group", style="red", width=20)
                victim_table.add_column("Date", style="dim", width=15)

                for victim in victims[:10]:  # Show first 10
                    if isinstance(victim, dict):
                        org = victim.get('post_title', victim.get('victim_name', 'Unknown'))
                        group = victim.get('group_name', 'Unknown')
                        date = victim.get('discovered', victim.get('published', 'N/A'))[:10]
                        victim_table.add_row(org, group, date)

                self.console.print(victim_table)

                if len(victims) > 10:
                    self.console.print(f"[dim]... and {len(victims) - 10} more victims[/dim]")

            # Display IOC database matches
            ioc_matches = data.get('ioc_database_matches', [])
            if ioc_matches:
                self.console.print(f"\n[bold red]IOC Database Matches ({len(ioc_matches)}):[/bold red]")
                ioc_table = Table(box=box.SIMPLE, padding=(0, 1))
                ioc_table.add_column("IOC", style="bold white", width=50)
                ioc_table.add_column("Type", style="cyan", width=15)
                ioc_table.add_column("Group", style="red", width=20)

                for ioc_entry in ioc_matches[:15]:  # Show first 15
                    if isinstance(ioc_entry, dict):
                        ioc_val = ioc_entry.get('ioc', ioc_entry.get('value', 'Unknown'))[:50]
                        ioc_type = ioc_entry.get('type', 'unknown')
                        group = ioc_entry.get('group_name', ioc_entry.get('group', 'Unknown'))
                        ioc_table.add_row(ioc_val, ioc_type, group)

                self.console.print(ioc_table)

                if len(ioc_matches) > 15:
                    self.console.print(f"[dim]... and {len(ioc_matches) - 15} more IOC matches[/dim]")

            # Display cyberattacks
            attacks = data.get('cyberattacks', [])
            if attacks:
                self.console.print(f"\n[bold]Cyberattacks Found ({len(attacks)}):[/bold]")
                for attack in attacks[:5]:  # Show first 5
                    if isinstance(attack, dict):
                        self.console.print(f"  • {attack.get('title', 'Unknown')} - {attack.get('date', 'N/A')}")
                if len(attacks) > 5:
                    self.console.print(f"[dim]... and {len(attacks) - 5} more attacks[/dim]")

        else:
            self.console.print(Panel(
                f"[green]✓ IOC NOT found in ransomware activity[/green]\n\n[bold white]IOC:[/bold white] {ioc}",
                border_style="green",
                title="Clean IOC"
            ))

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _search_ransomware_groups(self, client: 'RansomwareLiveClient') -> None:
        """Search and list ransomware groups"""
        self.console.print("\n[bold cyan]Ransomware Groups[/bold cyan]\n")

        # Ask user preference
        self.console.print("[dim]Display options:[/dim]")
        self.console.print("  [1] Simple list (fast)")
        self.console.print("  [2] Detailed table with stats (slower)\n")

        display_choice = self.console.input("Select display format [1]: ").strip() or "1"

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Fetching ransomware groups...", total=None)
            result = client.get_groups()
            progress.update(task, description="[green]✓ Groups loaded")
            time.sleep(0.3)

        if not result.success:
            self.console.print(f"[red]Error: {result.error}[/red]")
            return

        groups = result.data.get('groups', [])
        group_objects = result.data.get('group_objects', [])

        self.console.print(f"\n[bold]Known Ransomware Groups ({len(groups)}):[/bold]\n")

        if display_choice == "2":
            # Detailed view - use full group objects
            self.console.print("[dim]Processing group information...[/dim]")

            # DEBUG
            self.console.print(f"[dim]Debug: group_objects type: {type(group_objects)}, len: {len(group_objects) if isinstance(group_objects, list) else 'N/A'}[/dim]")
            if isinstance(group_objects, list) and len(group_objects) > 0:
                self.console.print(f"[dim]Debug: First item: {group_objects[0]}[/dim]")
            self.console.print()

            detailed_table = Table(box=box.SIMPLE, padding=(0, 1))
            detailed_table.add_column("Group", style="bold red", width=25)
            detailed_table.add_column("Status", style="cyan", width=12)
            detailed_table.add_column("Victims", style="yellow", justify="right", width=10)
            detailed_table.add_column("Last Seen", style="dim", width=15)

            # Ensure we have a list
            if not isinstance(group_objects, list):
                group_objects = []

            items_to_show = group_objects[:100] if len(group_objects) > 100 else group_objects

            for item in items_to_show:
                if isinstance(item, dict):
                    # Extract all possible fields
                    group_name = (
                        item.get('name') or
                        item.get('group') or
                        item.get('group_name') or
                        'Unknown'
                    )

                    # Try to get status from the group object itself
                    status = (
                        item.get('status') or
                        item.get('meta', {}).get('status') if isinstance(item.get('meta'), dict) else None or
                        item.get('profile', {}).get('status') if isinstance(item.get('profile'), dict) else None or
                        '-'
                    )

                    # Try to get victim count from the object
                    victims = (
                        item.get('victims') or
                        item.get('victim_count') or
                        item.get('posts') or
                        '-'
                    )

                    # Try to get last activity
                    last_seen = (
                        item.get('last_seen') or
                        item.get('lastseen') or
                        item.get('last_update') or
                        item.get('updated') or
                        '-'
                    )

                    # Format the data
                    detailed_table.add_row(
                        str(group_name)[:25],
                        str(status)[:12],
                        str(victims),
                        str(last_seen)[:15]
                    )
                else:
                    # Just a string name
                    detailed_table.add_row(str(item)[:25], '-', '-', '-')

            self.console.print(detailed_table)

            if len(group_objects) > 100:
                self.console.print(f"\n[dim]Showing first 100 of {len(group_objects)} groups[/dim]")

            self.console.print(f"\n[dim]Note: Data shown is from the groups list API. Some fields may be unavailable.[/dim]")
            self.console.print(f"[dim]Use Option 5 (Group Intelligence) to get full details for a specific group.[/dim]")

        else:
            # Simple 3-column view
            groups_table = Table(box=box.SIMPLE, padding=(0, 2), show_header=False)
            groups_table.add_column("Group 1", style="bold red")
            groups_table.add_column("Group 2", style="bold red")
            groups_table.add_column("Group 3", style="bold red")

            # Convert all groups to strings and sort alphabetically
            group_names = []
            for group in groups:
                if isinstance(group, dict):
                    # Extract name from dict
                    name = group.get('name', group.get('group', group.get('group_name', str(group))))
                    group_names.append(name)
                else:
                    group_names.append(str(group))

            sorted_groups = sorted(group_names, key=str.lower)

            # Split into 3 columns
            for i in range(0, len(sorted_groups), 3):
                row = sorted_groups[i:i+3]
                while len(row) < 3:
                    row.append("")
                groups_table.add_row(*row)

            self.console.print(groups_table)

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _search_victims(self, client: 'RansomwareLiveClient') -> None:
        """Search for victims by keyword"""
        self.console.print("\n[bold cyan]Search Ransomware Victims[/bold cyan]\n")

        # Show quick preview of recent activity first
        self.console.print("[dim]Tip: Checking if victim data is available...[/dim]")
        preview_result = client.get_recent_victims()
        if preview_result.success:
            victims = preview_result.data.get('victims', [])
            if victims:
                self.console.print(f"[green]✓ Victim database available ({len(victims)} recent victims)[/green]")
                # Show sample fields
                if isinstance(victims[0], dict):
                    sample_fields = list(victims[0].keys())
                    self.console.print(f"[dim]Available fields: {', '.join(sample_fields[:5])}...[/dim]")
            else:
                self.console.print("[yellow]⚠ No recent victims found in database[/yellow]")
        else:
            self.console.print(f"[yellow]⚠ Could not check victim database: {preview_result.error}[/yellow]")

        self.console.print()

        keyword = self.console.input("Enter search keyword (organization, domain, etc.): ").strip()
        if not keyword:
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[cyan]Searching victims for '{keyword}'...", total=None)
            result = client.search_victims(keyword)
            progress.update(task, description="[green]✓ Search complete")
            time.sleep(0.3)

        if not result.success:
            self.console.print(f"[red]Error: {result.error}[/red]")
            return

        victims = result.data.get('victims', [])

        if not victims:
            self.console.print(f"[yellow]No victims found matching '{keyword}'[/yellow]")
        else:
            self.console.print(f"\n[bold]Victims Found ({len(victims)}):[/bold]\n")

            victim_table = Table(box=box.SIMPLE, padding=(0, 1))
            victim_table.add_column("Organization", style="bold white", width=45)
            victim_table.add_column("Ransomware Group", style="red", width=20)
            victim_table.add_column("Published", style="dim", width=12)

            for victim in victims[:20]:  # Show first 20
                if isinstance(victim, dict):
                    org = victim.get('post_title', victim.get('victim_name', 'Unknown'))[:45]
                    group = victim.get('group_name', 'Unknown')
                    date = victim.get('discovered', victim.get('published', 'N/A'))[:10]
                    victim_table.add_row(org, group, date)

            self.console.print(victim_table)

            if len(victims) > 20:
                self.console.print(f"\n[dim]Showing 20 of {len(victims)} results[/dim]")

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _get_recent_activity(self, client: 'RansomwareLiveClient') -> None:
        """Get recent ransomware activity"""
        self.console.print("\n[bold cyan]Recent Ransomware Activity[/bold cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Fetching recent activity...", total=None)
            victims_result = client.get_recent_victims()
            attacks_result = client.get_cyberattacks(recent_only=True)
            progress.update(task, description="[green]✓ Data loaded")
            time.sleep(0.3)

        # Display recent victims
        if victims_result.success:
            victims = victims_result.data.get('victims', [])

            if victims:
                # DEBUG: Show what we actually got
                self.console.print(f"\n[yellow]DEBUG INFO:[/yellow]")
                self.console.print(f"[dim]Total victims: {len(victims)}[/dim]")
                self.console.print(f"[dim]First victim type: {type(victims[0])}[/dim]")
                if isinstance(victims[0], dict):
                    self.console.print(f"[dim]First victim keys: {list(victims[0].keys())}[/dim]")
                    self.console.print(f"[dim]First victim sample: {victims[0]}[/dim]")
                else:
                    self.console.print(f"[dim]First victim value: {victims[0]}[/dim]")
                self.console.print()

                self.console.print(f"\n[bold]Recent Victims ({len(victims)}):[/bold]\n")

                victim_table = Table(box=box.SIMPLE, padding=(0, 1))
                victim_table.add_column("Organization", style="bold white", width=45)
                victim_table.add_column("Group", style="red", width=20)
                victim_table.add_column("Date", style="dim", width=12)

                for victim in victims[:25]:  # Show first 25
                    if isinstance(victim, dict):
                        # Try multiple field name variations
                        org = (
                            victim.get('post_title') or
                            victim.get('victim_name') or
                            victim.get('victim') or
                            victim.get('name') or
                            victim.get('company') or
                            victim.get('organization') or
                            'Unknown'
                        )
                        group = (
                            victim.get('group_name') or
                            victim.get('group') or
                            victim.get('actor') or
                            'Unknown'
                        )
                        date = (
                            victim.get('discovered') or
                            victim.get('published') or
                            victim.get('date') or
                            victim.get('published_date') or
                            victim.get('post_date') or
                            'N/A'
                        )

                        # Format and truncate
                        org = str(org)[:45]
                        group = str(group)
                        date = str(date)[:10]

                        victim_table.add_row(org, group, date)

                self.console.print(victim_table)

                if len(victims) > 25:
                    self.console.print(f"\n[dim]Showing 25 of {len(victims)} recent victims[/dim]")
            else:
                self.console.print("\n[yellow]No recent victims found[/yellow]")
        else:
            self.console.print(f"\n[red]Error fetching victims: {victims_result.error}[/red]")

        # Display recent cyberattacks
        if attacks_result.success:
            attacks = attacks_result.data.get('attacks', [])
            if attacks:
                self.console.print(f"\n[bold]Recent Cyberattacks ({len(attacks)}):[/bold]\n")

                for attack in attacks[:10]:  # Show first 10
                    if isinstance(attack, dict):
                        title = attack.get('title', attack.get('name', 'Unknown'))
                        date = attack.get('date', 'N/A')
                        self.console.print(f"  • [{date}] {title}")

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _get_group_intelligence(self, client: 'RansomwareLiveClient') -> None:
        """Get detailed intelligence about a specific ransomware group"""
        self.console.print("\n[bold cyan]Ransomware Group Intelligence[/bold cyan]\n")

        group_name = self.console.input("Enter ransomware group name: ").strip()
        if not group_name:
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[cyan]Fetching comprehensive data for '{group_name}'...", total=None)

            # Get group info, victims, YARA rules, and IOCs
            info_result = client.get_group_info(group_name)
            victims_result = client.get_group_victims(group_name)
            yara_result = client.get_yara_rules(group_name)
            iocs_result = client.get_group_iocs(group_name)

            progress.update(task, description="[green]✓ Data loaded")
            time.sleep(0.3)

        if not info_result.success and not victims_result.success:
            self.console.print(f"[red]Group '{group_name}' not found[/red]")
            return

        # Display group information
        self.console.print(f"\n[bold red]{'=' * 80}[/bold red]")
        self.console.print(f"[bold red]RANSOMWARE GROUP: {group_name.upper()}[/bold red]")
        self.console.print(f"[bold red]{'=' * 80}[/bold red]\n")

        # Group info panel (enhanced)
        if info_result.success and info_result.data.get('found'):
            info = info_result.data.get('info', {})
            if isinstance(info, dict):
                # Extract profile information
                profile_list = info.get('profile', [])
                profile_text = 'N/A'
                if isinstance(profile_list, list) and profile_list:
                    profile_text = ' | '.join([str(p) for p in profile_list])
                elif isinstance(profile_list, str):
                    profile_text = profile_list

                # Extract infrastructure info
                locations = info.get('locations', [])
                active_sites = sum(1 for loc in locations if isinstance(loc, dict) and loc.get('available', False))
                total_sites = len(locations)

                # Description
                description = info.get('description', 'No description available')
                if not description or description == 'null' or description == '':
                    description = 'No description available'

                # Ransomware.live URL
                group_url = info.get('url', f'https://www.ransomware.live/group/{group_name}')

                info_text = f"""[bold]Group Name:[/bold] {group_name.upper()}
[bold]Status:[/bold] Active
[bold]Profile:[/bold] {profile_text}
[bold]Description:[/bold] {description}
[bold]Infrastructure:[/bold] {active_sites}/{total_sites} active sites
[bold]More Info:[/bold] {group_url}"""

                self.console.print(Panel(info_text, title="Group Profile", border_style="red", box=box.DOUBLE))

        # Victims section (enhanced with analytics)
        if victims_result.success:
            victims = victims_result.data.get('victims', [])
            victim_count = victims_result.data.get('victim_count', 0)

            # Analytics on victims
            country_stats = {}
            sector_stats = {}
            recent_attacks = []

            for victim in victims:
                if isinstance(victim, dict):
                    # Count by country
                    country = victim.get('country', 'Unknown')
                    country_stats[country] = country_stats.get(country, 0) + 1

                    # Count by sector/activity
                    sector = victim.get('activity', 'Unknown')
                    if sector and sector != '':
                        sector_stats[sector] = sector_stats.get(sector, 0) + 1

                    # Track recent attacks (last 90 days)
                    attack_date = victim.get('discovered', victim.get('attackdate', ''))
                    if attack_date:
                        try:
                            from datetime import datetime, timedelta
                            attack_dt = datetime.strptime(attack_date[:10], '%Y-%m-%d')
                            if datetime.now() - attack_dt < timedelta(days=90):
                                recent_attacks.append(victim)
                        except:
                            pass

            self.console.print(f"\n[bold]Victim Intelligence ({victim_count} total victims):[/bold]\n")

            # Show analytics
            if country_stats or sector_stats:
                analytics_table = Table(box=box.ROUNDED, title="Targeting Patterns", title_style="bold cyan")
                analytics_table.add_column("Top 5 Countries", style="yellow", width=30)
                analytics_table.add_column("Count", justify="right", style="bold", width=8)
                analytics_table.add_column("Top 5 Sectors", style="magenta", width=35)
                analytics_table.add_column("Count", justify="right", style="bold", width=8)

                sorted_countries = sorted(country_stats.items(), key=lambda x: x[1], reverse=True)[:5]
                sorted_sectors = sorted(sector_stats.items(), key=lambda x: x[1], reverse=True)[:5]

                max_rows = max(len(sorted_countries), len(sorted_sectors))
                for i in range(max_rows):
                    country = sorted_countries[i] if i < len(sorted_countries) else ('', '')
                    sector = sorted_sectors[i] if i < len(sorted_sectors) else ('', '')
                    analytics_table.add_row(
                        country[0] if country[0] else '',
                        str(country[1]) if country[1] else '',
                        sector[0] if sector[0] else '',
                        str(sector[1]) if sector[1] else ''
                    )

                self.console.print(analytics_table)
                self.console.print()

            # Recent activity indicator
            if recent_attacks:
                self.console.print(f"[bold yellow]⚠ Recent Activity:[/bold yellow] {len(recent_attacks)} attacks in last 90 days\n")

            # Victims table (enhanced with sector)
            if victims:
                victim_table = Table(box=box.SIMPLE, padding=(0, 1), title="Recent Victims", title_style="bold white")
                victim_table.add_column("Organization", style="bold white", width=35)
                victim_table.add_column("Sector", style="cyan", width=25)
                victim_table.add_column("Country", style="yellow", width=8)
                victim_table.add_column("Date", style="dim", width=10)

                for victim in victims[:25]:  # Show first 25
                    if isinstance(victim, dict):
                        org = victim.get('victim', victim.get('post_title', victim.get('victim_name', 'Unknown')))[:35]
                        sector = victim.get('activity', 'Unknown')[:25]
                        country = victim.get('country', 'N/A')
                        date = victim.get('discovered', victim.get('attackdate', 'N/A'))[:10]
                        victim_table.add_row(org, sector, country, date)

                self.console.print(victim_table)

                if victim_count > 25:
                    self.console.print(f"\n[dim]Showing 25 of {victim_count} victims[/dim]")
            else:
                self.console.print("[dim]No victims recorded[/dim]")

        # IOCs section (new)
        if iocs_result.success:
            iocs = iocs_result.data.get('iocs', [])
            if iocs:
                self.console.print(f"\n[bold]Indicators of Compromise ({len(iocs)} IOCs):[/bold]\n")

                # Group IOCs by type
                ioc_types = {}
                for ioc in iocs:
                    if isinstance(ioc, dict):
                        ioc_type = ioc.get('type', 'unknown')
                        if ioc_type not in ioc_types:
                            ioc_types[ioc_type] = []
                        ioc_types[ioc_type].append(ioc.get('ioc', ioc.get('value', 'N/A')))

                # Display IOCs by type
                ioc_table = Table(box=box.SIMPLE, padding=(0, 1))
                ioc_table.add_column("Type", style="cyan", width=15)
                ioc_table.add_column("Count", style="bold", width=8)
                ioc_table.add_column("Sample Values", style="dim", width=55)

                for ioc_type, values in ioc_types.items():
                    sample = ', '.join(values[:3])
                    if len(values) > 3:
                        sample += '...'
                    ioc_table.add_row(ioc_type, str(len(values)), sample)

                self.console.print(ioc_table)
                self.console.print(f"\n[dim]Full IOC list: {info.get('url', f'https://www.ransomware.live/group/{group_name}')}[/dim]")

        # YARA rules
        if yara_result.success and yara_result.data.get('has_rules'):
            yara_rules = yara_result.data.get('yara_rules', '')
            if yara_rules:
                self.console.print(f"\n[bold green]✓ YARA Rules Available[/bold green]")
                self.console.print("[dim]YARA rules can be used for detection and hunting[/dim]")

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _get_all_iocs(self, client: 'RansomwareLiveClient') -> None:
        """Get all IOCs from ransomware groups (PRO feature)"""
        self.console.print("\n[bold cyan]All Ransomware IOCs[/bold cyan]\n")

        if not client.use_pro:
            self.console.print("[red]This feature requires API PRO subscription[/red]")
            self.console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Fetching all IOCs...", total=None)
            result = client.get_all_iocs()
            progress.update(task, description="[green]✓ IOCs loaded")
            time.sleep(0.3)

        if not result.success:
            self.console.print(f"[red]Error: {result.error}[/red]")
            self.console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return

        iocs = result.data.get('iocs', [])

        # Filter out entries with no actual IOC data (N/A values)
        valid_iocs = [ioc for ioc in iocs if isinstance(ioc, dict) and ioc.get('ioc', 'N/A') != 'N/A']

        if not iocs:
            self.console.print("[yellow]No IOCs found[/yellow]")
        elif not valid_iocs:
            self.console.print(f"[yellow]Found {len(iocs)} ransomware groups, but IOCs are not included in this endpoint.[/yellow]")
            self.console.print(f"\n[dim]Tip: Use the individual group IOC endpoint to get IOCs for a specific group.[/dim]")
            self.console.print(f"[dim]Would you like to fetch IOCs for a specific group?[/dim]\n")

            group_choice = self.console.input("Enter group name (or press Enter to skip): ").strip()
            if group_choice:
                # Fetch IOCs for specific group
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=self.console,
                    transient=True
                ) as progress:
                    task = progress.add_task(f"[cyan]Fetching IOCs for {group_choice}...", total=None)
                    group_result = client.get_group_iocs(group_choice)
                    progress.update(task, description=f"[green]✓ IOCs for {group_choice} loaded")
                    time.sleep(0.3)

                if group_result.success:
                    group_iocs = group_result.data.get('iocs', [])
                    if group_iocs:
                        self.console.print(f"\n[bold green]Found {len(group_iocs)} IOCs for {group_choice}:[/bold green]\n")
                        iocs = group_iocs
                        valid_iocs = iocs  # Display these IOCs
                    else:
                        self.console.print(f"[yellow]No IOCs found for group '{group_choice}'[/yellow]")
                else:
                    self.console.print(f"[yellow]IOCs not available via API for '{group_choice}': {group_result.error}[/yellow]")
                    self.console.print(f"\n[dim]Note: The API may not expose all IOCs that are visible on the website.[/dim]")
                    self.console.print(f"[dim]Suggestion: Visit https://www.ransomware.live/groups/{group_choice.lower()} for full IOC data,[/dim]")
                    self.console.print(f"[dim]or try Option 5 (Group Intelligence) for group details and YARA rules.[/dim]")
        else:
            self.console.print(f"\n[bold]Total IOCs Found: {len(valid_iocs)}[/bold]\n")
            iocs = valid_iocs  # Use only valid IOCs for display

            # Group IOCs by type
            from collections import defaultdict
            by_type = defaultdict(list)

            for ioc in iocs:
                if isinstance(ioc, dict):
                    ioc_type = ioc.get('type', 'unknown')
                    by_type[ioc_type].append(ioc)

            # Display summary
            summary_table = Table(box=box.SIMPLE, padding=(0, 1))
            summary_table.add_column("IOC Type", style="bold cyan", width=20)
            summary_table.add_column("Count", justify="center", width=10)

            for ioc_type, items in sorted(by_type.items()):
                summary_table.add_row(ioc_type.upper(), str(len(items)))

            self.console.print(summary_table)

            # Display sample IOCs
            self.console.print(f"\n[bold]Sample IOCs (first 20):[/bold]\n")
            ioc_table = Table(box=box.SIMPLE, padding=(0, 1))
            ioc_table.add_column("IOC", style="bold white", width=50)
            ioc_table.add_column("Type", style="cyan", width=15)
            ioc_table.add_column("Group", style="red", width=20)

            for ioc in iocs[:20]:
                if isinstance(ioc, dict):
                    ioc_value = ioc.get('ioc', ioc.get('value', 'N/A'))[:50]
                    ioc_type = ioc.get('type', 'unknown')
                    group = ioc.get('group', ioc.get('group_name', 'Unknown'))
                    ioc_table.add_row(ioc_value, ioc_type, group)

            self.console.print(ioc_table)

            if len(iocs) > 20:
                self.console.print(f"\n[dim]Showing 20 of {len(iocs)} IOCs[/dim]")

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _view_negotiations(self, client: 'RansomwareLiveClient') -> None:
        """View ransomware negotiation chat logs (PRO feature)"""
        self.console.print("\n[bold cyan]Ransomware Negotiation Chat Logs[/bold cyan]\n")

        if not client.use_pro:
            self.console.print("[red]This feature requires API PRO subscription[/red]")
            self.console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return

        # First, fetch all negotiations to show which groups have data
        self.console.print("[dim]Checking which groups have negotiation chats available...[/dim]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Fetching available chats...", total=None)
            all_negotiations_result = client.get_negotiations(None)
            progress.update(task, description="[green]✓ Chats loaded")
            time.sleep(0.3)

        # Extract groups that have negotiations
        groups_with_negotiations = set()
        if all_negotiations_result.success:
            negotiations = all_negotiations_result.data.get('negotiations', [])
            if isinstance(negotiations, list):
                for negotiation in negotiations:
                    if isinstance(negotiation, dict):
                        group = negotiation.get('group_name', negotiation.get('group', ''))
                        if group:
                            groups_with_negotiations.add(group)

        if groups_with_negotiations:
            self.console.print(f"[green]✓ Found negotiation chats for {len(groups_with_negotiations)} groups:[/green]\n")

            # Display groups with negotiations in columns
            sorted_groups = sorted(groups_with_negotiations, key=str.lower)
            groups_table = Table(box=box.SIMPLE, padding=(0, 2), show_header=False)
            groups_table.add_column("Group 1", style="cyan")
            groups_table.add_column("Group 2", style="cyan")
            groups_table.add_column("Group 3", style="cyan")

            for i in range(0, len(sorted_groups), 3):
                row = sorted_groups[i:i+3]
                while len(row) < 3:
                    row.append("")
                groups_table.add_row(*row)

            self.console.print(groups_table)
            self.console.print()
        else:
            self.console.print("[yellow]No groups with negotiation chats found[/yellow]\n")

        group_name = self.console.input("Enter group name from the list above (or press Enter for all): ").strip()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Fetching negotiations...", total=None)
            result = client.get_negotiations(group_name if group_name else None)
            progress.update(task, description="[green]✓ Negotiations loaded")
            time.sleep(0.3)

        if not result.success:
            self.console.print(f"[yellow]No negotiations found: {result.error}[/yellow]")
            if "404" in str(result.error) or "not found" in str(result.error).lower():
                self.console.print("\n[dim]Tip: Not all ransomware groups have negotiation chats available.[/dim]")
                self.console.print("[dim]Try checking a different group or press Enter without a group name to see all available chats.[/dim]")
            self.console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return

        negotiations = result.data.get('negotiations', [])

        if not negotiations:
            self.console.print("[yellow]No negotiation logs found[/yellow]")
        else:
            count = len(negotiations) if isinstance(negotiations, list) else 1
            self.console.print(f"\n[bold]Negotiation Chats Found: {count}[/bold]\n")

            if isinstance(negotiations, list):
                for i, chat in enumerate(negotiations[:10], 1):
                    if isinstance(chat, dict):
                        chat_group = chat.get('group_name', 'Unknown')
                        chat_id = chat.get('chat_id', chat.get('id', 'N/A'))
                        timestamp = chat.get('timestamp', chat.get('date', 'N/A'))

                        self.console.print(f"[bold cyan]{i}. Group:[/bold cyan] {chat_group}")
                        self.console.print(f"   [dim]ID: {chat_id} | Date: {timestamp}[/dim]")

                        # Show preview of conversation
                        messages = chat.get('messages', chat.get('conversation', []))
                        if messages and isinstance(messages, list):
                            self.console.print(f"   [yellow]Messages: {len(messages)}[/yellow]")
                            if messages:
                                first_msg = messages[0]
                                if isinstance(first_msg, dict):
                                    preview = first_msg.get('message', first_msg.get('text', ''))[:80]
                                    self.console.print(f"   [dim]Preview: {preview}...[/dim]")
                        self.console.print()

                if len(negotiations) > 10:
                    self.console.print(f"[dim]Showing 10 of {len(negotiations)} negotiation chats[/dim]")

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _view_ransom_notes(self, client: 'RansomwareLiveClient') -> None:
        """View ransom notes from ransomware groups (PRO feature)"""
        self.console.print("\n[bold cyan]Ransomware Ransom Notes[/bold cyan]\n")

        if not client.use_pro:
            self.console.print("[red]This feature requires API PRO subscription[/red]")
            self.console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return

        # First, fetch all notes to show which groups have data
        self.console.print("[dim]Checking which groups have ransom notes available...[/dim]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Fetching available notes...", total=None)
            all_notes_result = client.get_ransom_notes(None)
            progress.update(task, description="[green]✓ Notes loaded")
            time.sleep(0.3)

        # Extract groups that have notes
        groups_with_notes = set()
        if all_notes_result.success:
            notes = all_notes_result.data.get('ransom_notes', [])
            if isinstance(notes, list):
                for note in notes:
                    if isinstance(note, dict):
                        group = note.get('group_name', note.get('group', ''))
                        if group:
                            groups_with_notes.add(group)

        if groups_with_notes:
            self.console.print(f"[green]✓ Found ransom notes for {len(groups_with_notes)} groups:[/green]\n")

            # Display groups with notes in columns
            sorted_groups = sorted(groups_with_notes, key=str.lower)
            groups_table = Table(box=box.SIMPLE, padding=(0, 2), show_header=False)
            groups_table.add_column("Group 1", style="cyan")
            groups_table.add_column("Group 2", style="cyan")
            groups_table.add_column("Group 3", style="cyan")

            for i in range(0, len(sorted_groups), 3):
                row = sorted_groups[i:i+3]
                while len(row) < 3:
                    row.append("")
                groups_table.add_row(*row)

            self.console.print(groups_table)
            self.console.print()
        else:
            self.console.print("[yellow]No groups with ransom notes found[/yellow]\n")

        group_name = self.console.input("Enter group name from the list above (or press Enter for all): ").strip()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Fetching ransom notes...", total=None)
            result = client.get_ransom_notes(group_name if group_name else None)
            progress.update(task, description="[green]✓ Notes loaded")
            time.sleep(0.3)

        if not result.success:
            self.console.print(f"[yellow]No ransom notes found: {result.error}[/yellow]")
            if "404" in str(result.error) or "not found" in str(result.error).lower():
                self.console.print("\n[dim]Tip: Not all ransomware groups have ransom notes available.[/dim]")
                self.console.print("[dim]Try checking a different group or press Enter to see all available notes.[/dim]")
            self.console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return

        notes = result.data.get('ransom_notes', [])

        if not notes:
            self.console.print("[yellow]No ransom notes found[/yellow]")
        else:
            count = len(notes) if isinstance(notes, list) else 1
            self.console.print(f"\n[bold]Ransom Notes Found: {count}[/bold]\n")

            if isinstance(notes, list):
                note_table = Table(box=box.SIMPLE, padding=(0, 1))
                note_table.add_column("Group", style="bold red", width=20)
                note_table.add_column("Note Name", style="cyan", width=30)
                note_table.add_column("Size", style="dim", width=10)
                note_table.add_column("Preview", style="white", width=40)

                for note in notes[:15]:
                    if isinstance(note, dict):
                        note_group = note.get('group_name', note.get('group', 'Unknown'))
                        note_name = note.get('note_name', note.get('filename', 'N/A'))
                        note_content = note.get('content', note.get('text', ''))
                        size = f"{len(note_content)} chars" if note_content else "N/A"
                        preview = note_content[:40] + "..." if len(note_content) > 40 else note_content

                        note_table.add_row(note_group, note_name, size, preview)

                self.console.print(note_table)

                if len(notes) > 15:
                    self.console.print(f"\n[dim]Showing 15 of {len(notes)} ransom notes[/dim]")

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _view_statistics(self, client: 'RansomwareLiveClient') -> None:
        """View ransomware statistics and analytics (PRO feature)"""
        self.console.print("\n[bold cyan]Ransomware Activity Statistics[/bold cyan]\n")

        if not client.use_pro:
            self.console.print("[red]This feature requires API PRO subscription[/red]")
            self.console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            # Fetch multiple data sources for comprehensive statistics
            task1 = progress.add_task("[cyan]Fetching statistics...", total=None)
            result = client.get_statistics()
            progress.update(task1, description="[green]✓ Statistics loaded")

            task2 = progress.add_task("[cyan]Fetching groups...", total=None)
            groups_result = client.get_groups()
            progress.update(task2, description="[green]✓ Groups loaded")

            task3 = progress.add_task("[cyan]Fetching recent victims...", total=None)
            victims_result = client.get_recent_victims()
            progress.update(task3, description="[green]✓ Victims loaded")

            time.sleep(0.3)

        # Even if stats endpoint fails, we can still show analytics from other sources
        stats = result.data.get('statistics', {}) if result.success else {}

        if not stats:
            self.console.print("[yellow]No statistics available[/yellow]")
        else:
            self.console.print("[bold]Ransomware Activity Overview[/bold]\n")

            # Overall statistics panel
            if isinstance(stats, dict):
                # Get the actual client email if available
                client_info = ""
                if hasattr(client, 'session') and hasattr(client.session, 'headers'):
                    api_key = client.session.headers.get('X-Api-Key', '')
                    if api_key:
                        # We could make a validate call, but let's just use what we have
                        client_info = "API PRO Client\n"

                overall_text = ""

                # Primary stats that we know exist from the output
                victims = stats.get('victims', 0)
                groups = stats.get('groups', 0)
                press = stats.get('press', 0)

                if victims or groups or press:
                    overall_text += f"[bold white]Total Victims:[/bold white] [red]{victims:,}[/red]\n"
                    overall_text += f"[bold white]Active Ransomware Groups:[/bold white] [red]{groups:,}[/red]\n"
                    overall_text += f"[bold white]Press Releases & 8-K Filings:[/bold white] [cyan]{press:,}[/cyan]\n"

                # Common stat fields to check
                stat_fields = [
                    ('total_cyberattacks', 'Total Cyberattacks'),
                    ('victims_this_month', 'Victims This Month'),
                    ('victims_this_year', 'Victims This Year'),
                    ('average_per_month', 'Average Victims/Month'),
                    ('average_per_day', 'Average Victims/Day')
                ]

                for key, label in stat_fields:
                    if key in stats:
                        overall_text += f"[bold]{label}:[/bold] {stats[key]:,}\n"

                # Display any other numeric stats
                displayed_keys = {'victims', 'groups', 'press'} | {k for k, _ in stat_fields}
                for key, value in stats.items():
                    if key not in displayed_keys:
                        label = key.replace('_', ' ').title()
                        if isinstance(value, (int, float)):
                            overall_text += f"[bold]{label}:[/bold] {value:,}\n"
                        elif isinstance(value, str) and len(str(value)) < 50:
                            overall_text += f"[bold]{label}:[/bold] {value}\n"

                if overall_text:
                    self.console.print(Panel(overall_text.strip(), title="Overall Statistics", border_style="cyan"))

                # Calculate and display interesting metrics
                if victims and groups:
                    avg_victims_per_group = victims / groups
                    self.console.print(f"\n[dim]Average victims per group: {avg_victims_per_group:.1f}[/dim]")

                # Estimate activity trends
                from datetime import datetime
                current_year = datetime.now().year
                # Estimate based on total victims (assuming tracking started around 2019)
                years_tracked = current_year - 2019
                if years_tracked > 0:
                    avg_per_year = victims / years_tracked
                    self.console.print(f"[dim]Estimated average per year: {avg_per_year:.0f} victims[/dim]")

                self.console.print()

                # Top groups by victims
                if 'top_groups' in stats:
                    top_groups = stats['top_groups']
                    if isinstance(top_groups, list):
                        self.console.print("\n[bold]Top Ransomware Groups:[/bold]\n")

                        group_table = Table(box=box.SIMPLE, padding=(0, 1))
                        group_table.add_column("Rank", style="dim", width=6)
                        group_table.add_column("Group", style="bold red", width=25)
                        group_table.add_column("Victims", style="cyan", justify="center", width=10)

                        for i, group in enumerate(top_groups[:10], 1):
                            if isinstance(group, dict):
                                group_name = group.get('name', group.get('group_name', 'Unknown'))
                                victim_count = group.get('victims', group.get('victim_count', 0))
                                group_table.add_row(f"#{i}", group_name, str(victim_count))

                        self.console.print(group_table)

                # Country statistics
                if 'by_country' in stats or 'top_countries' in stats:
                    country_data = stats.get('by_country', stats.get('top_countries', []))
                    if isinstance(country_data, list) and country_data:
                        self.console.print("\n[bold]Top Targeted Countries:[/bold]\n")

                        country_table = Table(box=box.SIMPLE, padding=(0, 1))
                        country_table.add_column("Rank", style="dim", width=6)
                        country_table.add_column("Country", style="bold white", width=20)
                        country_table.add_column("Victims", style="yellow", justify="center", width=10)

                        for i, country in enumerate(country_data[:10], 1):
                            if isinstance(country, dict):
                                country_name = country.get('country', country.get('name', 'Unknown'))
                                victim_count = country.get('victims', country.get('count', 0))
                                country_table.add_row(f"#{i}", country_name, str(victim_count))

                        self.console.print(country_table)

                # Sector statistics
                if 'by_sector' in stats or 'top_sectors' in stats:
                    sector_data = stats.get('by_sector', stats.get('top_sectors', []))
                    if isinstance(sector_data, list) and sector_data:
                        self.console.print("\n[bold]Top Targeted Sectors:[/bold]\n")

                        sector_table = Table(box=box.SIMPLE, padding=(0, 1))
                        sector_table.add_column("Rank", style="dim", width=6)
                        sector_table.add_column("Sector", style="bold cyan", width=30)
                        sector_table.add_column("Victims", style="magenta", justify="center", width=10)

                        for i, sector in enumerate(sector_data[:10], 1):
                            if isinstance(sector, dict):
                                sector_name = sector.get('sector', sector.get('name', 'Unknown'))
                                victim_count = sector.get('victims', sector.get('count', 0))
                                sector_table.add_row(f"#{i}", sector_name, str(victim_count))

                        self.console.print(sector_table)

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()

    def _view_press_and_filings(self, client: 'RansomwareLiveClient') -> None:
        """View press releases and 8-K filings (PRO feature)"""
        self.console.print("\n[bold cyan]Press Releases & SEC 8-K Filings[/bold cyan]\n")

        if not client.use_pro:
            self.console.print("[red]This feature requires API PRO subscription[/red]")
            self.console.print("\n[dim]Press Enter to continue...[/dim]")
            input()
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task1 = progress.add_task("[cyan]Fetching press releases...", total=None)
            press_result = client.get_press_releases(recent_only=True)
            progress.update(task1, description="[green]✓ Press releases loaded")
            time.sleep(0.2)

            task2 = progress.add_task("[cyan]Fetching 8-K filings...", total=None)
            filings_result = client.get_8k_filings()
            progress.update(task2, description="[green]✓ 8-K filings loaded")
            time.sleep(0.2)

        # Display press releases
        if press_result.success:
            press = press_result.data.get('press_releases', [])
            if press:
                self.console.print(f"\n[bold]Recent Press Releases ({len(press)}):[/bold]\n")

                press_table = Table(box=box.SIMPLE, padding=(0, 1))
                press_table.add_column("Date", style="dim", width=12)
                press_table.add_column("Title", style="bold white", width=60)
                press_table.add_column("Source", style="cyan", width=20)

                for item in press[:15]:
                    if isinstance(item, dict):
                        date = item.get('date', item.get('published', 'N/A'))[:10]
                        title = item.get('title', item.get('headline', 'N/A'))[:60]
                        source = item.get('source', item.get('publisher', 'N/A'))[:20]
                        press_table.add_row(date, title, source)

                self.console.print(press_table)

                if len(press) > 15:
                    self.console.print(f"\n[dim]Showing 15 of {len(press)} press releases[/dim]")
            else:
                self.console.print("[yellow]No press releases found[/yellow]")

        # Display 8-K filings
        if filings_result.success:
            filings = filings_result.data.get('8k_filings', [])
            if filings:
                self.console.print(f"\n\n[bold]SEC 8-K Filings ({len(filings)}):[/bold]\n")

                filings_table = Table(box=box.SIMPLE, padding=(0, 1))
                filings_table.add_column("Date", style="dim", width=12)
                filings_table.add_column("Company", style="bold yellow", width=35)
                filings_table.add_column("Filing Type", style="cyan", width=15)
                filings_table.add_column("Description", style="white", width=40)

                for filing in filings[:15]:
                    if isinstance(filing, dict):
                        date = filing.get('filing_date', filing.get('date', 'N/A'))[:10]
                        company = filing.get('company', filing.get('company_name', 'N/A'))[:35]
                        filing_type = filing.get('type', '8-K')
                        desc = filing.get('description', filing.get('summary', 'N/A'))[:40]
                        filings_table.add_row(date, company, filing_type, desc)

                self.console.print(filings_table)

                if len(filings) > 15:
                    self.console.print(f"\n[dim]Showing 15 of {len(filings)} SEC filings[/dim]")
            else:
                self.console.print("\n[yellow]No 8-K filings found[/yellow]")

        self.console.print("\n[dim]Press Enter to continue...[/dim]")
        input()
