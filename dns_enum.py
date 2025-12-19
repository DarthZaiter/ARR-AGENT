#!/usr/bin/env python3
"""
DNS Enumeration Module for ARR-Agent
Performs DNS lookups and WHOIS queries
"""

import socket
import subprocess
import json
from datetime import datetime

class DNSEnumerator:
    """DNS and WHOIS enumeration module"""
    
    def __init__(self, agent):
        self.agent = agent
        self.target = agent.target
    
    def enumerate(self):
        """Perform comprehensive DNS enumeration"""
        print(f"[*] Starting DNS enumeration for {self.target}")
        
        # Perform various DNS lookups
        self._lookup_a_records()
        self._lookup_aaaa_records()
        self._lookup_mx_records()
        self._lookup_ns_records()
        self._lookup_txt_records()
        self._lookup_soa_record()
        
        # Attempt WHOIS lookup
        self._whois_lookup()
        
        print(f"[+] DNS enumeration complete")
    
    def _lookup_a_records(self):
        """Look up A records (IPv4)"""
        try:
            result = socket.gethostbyname_ex(self.target)
            
            for ip in result[2]:
                self._save_dns_record('A', ip)
                print(f"    [+] A Record: {self.target} -> {ip}")
                
                # Store as primary IP if not set
                if 'primary_ip' not in self.agent.findings['dns']:
                    self.agent.findings['dns']['primary_ip'] = ip
                    
        except socket.gaierror:
            print(f"    [-] No A records found")
    
    def _lookup_aaaa_records(self):
        """Look up AAAA records (IPv6)"""
        try:
            result = socket.getaddrinfo(self.target, None, socket.AF_INET6)
            
            ipv6_addresses = set()
            for item in result:
                ipv6 = item[4][0]
                ipv6_addresses.add(ipv6)
            
            for ipv6 in ipv6_addresses:
                self._save_dns_record('AAAA', ipv6)
                print(f"    [+] AAAA Record: {self.target} -> {ipv6}")
                
        except socket.gaierror:
            print(f"    [-] No AAAA records found")
    
    def _lookup_mx_records(self):
        """Look up MX records (Mail Servers)"""
        try:
            result = subprocess.run(
                ['nslookup', '-query=mx', self.target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            lines = result.stdout.split('\n')
            for line in lines:
                if 'mail exchanger' in line.lower():
                    parts = line.split('=')
                    if len(parts) == 2:
                        mx_server = parts[1].strip()
                        self._save_dns_record('MX', mx_server)
                        print(f"    [+] MX Record: {mx_server}")
                        
        except Exception as e:
            print(f"    [-] MX lookup failed: {e}")
    
    def _lookup_ns_records(self):
        """Look up NS records (Name Servers)"""
        try:
            result = subprocess.run(
                ['nslookup', '-query=ns', self.target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            lines = result.stdout.split('\n')
            for line in lines:
                if 'nameserver' in line.lower():
                    parts = line.split('=')
                    if len(parts) == 2:
                        ns_server = parts[1].strip()
                        self._save_dns_record('NS', ns_server)
                        print(f"    [+] NS Record: {ns_server}")
                        
        except Exception as e:
            print(f"    [-] NS lookup failed: {e}")
    
    def _lookup_txt_records(self):
        """Look up TXT records"""
        try:
            result = subprocess.run(
                ['nslookup', '-query=txt', self.target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            lines = result.stdout.split('\n')
            for line in lines:
                if 'text =' in line.lower():
                    txt_value = line.split('=', 1)[1].strip().strip('"')
                    self._save_dns_record('TXT', txt_value)
                    print(f"    [+] TXT Record: {txt_value[:80]}...")
                    
        except Exception as e:
            print(f"    [-] TXT lookup failed: {e}")
    
    def _lookup_soa_record(self):
        """Look up SOA record (Start of Authority)"""
        try:
            result = subprocess.run(
                ['nslookup', '-query=soa', self.target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if 'origin' in result.stdout.lower():
                self._save_dns_record('SOA', result.stdout)
                print(f"    [+] SOA Record found")
                
        except Exception as e:
            print(f"    [-] SOA lookup failed: {e}")
    
    def _whois_lookup(self):
        """Perform WHOIS lookup"""
        print(f"[*] Performing WHOIS lookup...")
        
        try:
            result = subprocess.run(
                ['whois', self.target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            whois_data = result.stdout
            
            if whois_data:
                # Save full WHOIS data
                self._save_dns_record('WHOIS', whois_data)
                
                # Parse interesting fields
                interesting_fields = [
                    'Registrar:',
                    'Creation Date:',
                    'Expiration Date:',
                    'Name Server:',
                    'Registrant Organization:',
                    'Admin Email:'
                ]
                
                for line in whois_data.split('\n'):
                    for field in interesting_fields:
                        if field.lower() in line.lower():
                            print(f"    [+] {line.strip()}")
                            break
                
                # Store in findings
                self.agent.findings['dns']['whois'] = whois_data
                
        except FileNotFoundError:
            print(f"    [-] whois command not found. Install with: apt-get install whois")
        except Exception as e:
            print(f"    [-] WHOIS lookup failed: {e}")
    
    def _save_dns_record(self, record_type, value):
        """Save DNS record to database"""
        finding_data = {
            'domain': self.target,
            'record_type': record_type,
            'value': value
        }
        
        self.agent.save_finding('dns_records', finding_data)