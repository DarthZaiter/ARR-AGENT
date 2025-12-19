#!/usr/bin/env python3
"""
ARR-Agent: Autonomous Reconnaissance & Reporting Agent
Main framework for automated OSINT collection and vulnerability mapping
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
import sqlite3

class ARRAgent:
    """Main ARR-Agent orchestrator"""
    
    def __init__(self, target, output_dir="./arr_output"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.db_path = self.output_dir / f"arr_data_{self.session_id}.db"
        
        # Initialize database
        self._init_database()
        
        # Store for all findings
        self.findings = {
            'ports': [],
            'dns': {},
            'subdomains': [],
            'secrets': [],
            'risks': []
        }
        
        print(f"[+] ARR-Agent initialized for target: {target}")
        print(f"[+] Session ID: {self.session_id}")
        print(f"[+] Output directory: {self.output_dir}")
    
    def _init_database(self):
        """Initialize SQLite database for storing findings"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT,
                port INTEGER,
                protocol TEXT,
                state TEXT,
                service TEXT,
                version TEXT,
                timestamp TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                record_type TEXT,
                value TEXT,
                timestamp TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain TEXT UNIQUE,
                ip_address TEXT,
                timestamp TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                secret_type TEXT,
                value TEXT,
                context TEXT,
                timestamp TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_type TEXT,
                finding_id INTEGER,
                risk_score REAL,
                risk_factors TEXT,
                timestamp TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"[+] Database initialized: {self.db_path}")
    
    def save_finding(self, table, data):
        """Save a finding to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        data['timestamp'] = datetime.now().isoformat()
        
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['?' for _ in data])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        
        cursor.execute(query, list(data.values()))
        conn.commit()
        finding_id = cursor.lastrowid
        conn.close()
        
        return finding_id
    
    def run_module(self, module_name):
        """Run a specific reconnaissance module"""
        print(f"\n[*] Running module: {module_name}")
        
        if module_name == "portscan":
            from modules.port_scanner import PortScanner
            scanner = PortScanner(self)
            scanner.scan()
        
        elif module_name == "dns":
            from modules.dns_enum import DNSEnumerator
            enumerator = DNSEnumerator(self)
            enumerator.enumerate()
        
        elif module_name == "subdomains":
            from modules.subdomain_discovery import SubdomainDiscovery
            discovery = SubdomainDiscovery(self)
            discovery.discover()
        
        elif module_name == "secrets":
            from modules.github_secrets import GitHubSecretScanner
            scanner = GitHubSecretScanner(self)
            scanner.scan()
        
        else:
            print(f"[-] Unknown module: {module_name}")
    
    def run_all_modules(self):
        """Run all reconnaissance modules in sequence"""
        modules = ["dns", "subdomains", "portscan", "secrets"]
        
        for module in modules:
            try:
                self.run_module(module)
            except Exception as e:
                print(f"[-] Error in module {module}: {e}")
                continue
    
    def calculate_risk_scores(self):
        """Calculate ML-based risk scores for all findings"""
        print("\n[*] Calculating risk scores...")
        
        from modules.risk_scorer import RiskScorer
        scorer = RiskScorer(self)
        scorer.score_all_findings()
    
    def generate_report(self):
        """Generate comprehensive Markdown report"""
        print("\n[*] Generating report...")
        
        from modules.report_generator import ReportGenerator
        generator = ReportGenerator(self)
        report_path = generator.generate()
        
        print(f"[+] Report generated: {report_path}")
        return report_path


def main():
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║     █████╗ ██████╗ ██████╗       █████╗  ██████╗     ║
    ║    ██╔══██╗██╔══██╗██╔══██╗     ██╔══██╗██╔════╝     ║
    ║    ███████║██████╔╝██████╔╝     ███████║██║  ███╗    ║
    ║    ██╔══██║██╔══██╗██╔══██╗     ██╔══██║██║   ██║    ║
    ║    ██║  ██║██║  ██║██║  ██║     ██║  ██║╚██████╔╝    ║
    ║    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚═╝  ╚═╝ ╚═════╝     ║
    ║                                                       ║
    ║    Autonomous Reconnaissance & Reporting Agent        ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """
    
    print(banner)
    
    parser = argparse.ArgumentParser(
        description="ARR-Agent: Autonomous Reconnaissance & Reporting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('-o', '--output', default='./arr_output', 
                       help='Output directory (default: ./arr_output)')
    parser.add_argument('-m', '--module', 
                       choices=['portscan', 'dns', 'subdomains', 'secrets', 'all'],
                       default='all',
                       help='Specific module to run (default: all)')
    parser.add_argument('--no-risk-scoring', action='store_true',
                       help='Skip ML-based risk scoring')
    parser.add_argument('--no-report', action='store_true',
                       help='Skip report generation')
    
    args = parser.parse_args()
    
    # Initialize agent
    agent = ARRAgent(args.target, args.output)
    
    try:
        # Run modules
        if args.module == 'all':
            agent.run_all_modules()
        else:
            agent.run_module(args.module)
        
        # Calculate risk scores
        if not args.no_risk_scoring:
            agent.calculate_risk_scores()
        
        # Generate report
        if not args.no_report:
            agent.generate_report()
        
        print("\n[+] ARR-Agent scan complete!")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()