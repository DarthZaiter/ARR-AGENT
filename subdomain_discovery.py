#!/usr/bin/env python3
"""
Subdomain Discovery Module for ARR-Agent
Discovers subdomains using multiple techniques
"""

import socket
import subprocess
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class SubdomainDiscovery:
    """Subdomain discovery module"""
    
    def __init__(self, agent):
        self.agent = agent
        self.target = agent.target
        self.discovered = set()
    
    def discover(self):
        """Perform subdomain discovery using multiple methods"""
        print(f"[*] Starting subdomain discovery for {self.target}")
        
        # Method 1: Common subdomain bruteforce
        self._bruteforce_common()
        
        # Method 2: Certificate transparency logs
        self._cert_transparency()
        
        # Method 3: DNS zone transfer attempt
        self._zone_transfer_attempt()
        
        print(f"[+] Subdomain discovery complete. Found {len(self.discovered)} subdomains")
    
    def _bruteforce_common(self):
        """Bruteforce common subdomain names"""
        print("[*] Bruteforcing common subdomains...")
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'ns', 'test', 'dev', 'staging', 'prod', 'production', 'api', 'admin',
            'portal', 'vpn', 'remote', 'git', 'gitlab', 'jenkins', 'jira',
            'confluence', 'wiki', 'blog', 'shop', 'store', 'cdn', 'assets',
            'static', 'media', 'images', 'upload', 'downloads', 'm', 'mobile',
            'beta', 'alpha', 'demo', 'sandbox', 'secure', 'login', 'sso',
            'intranet', 'extranet', 'support', 'help', 'docs', 'status',
            'monitoring', 'grafana', 'prometheus', 'kibana', 'elastic'
        ]
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.target}"
            try:
                ip = socket.gethostbyname(full_domain)
                return (full_domain, ip)
            except socket.gaierror:
                return None
        
        # Use threading for faster scanning
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, sub): sub 
                      for sub in common_subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ip = result
                    if subdomain not in self.discovered:
                        self.discovered.add(subdomain)
                        self._save_subdomain(subdomain, ip)
                        print(f"    [+] Found: {subdomain} -> {ip}")
    
    def _cert_transparency(self):
        """Query Certificate Transparency logs"""
        print("[*] Checking Certificate Transparency logs...")
        
        try:
            # Query crt.sh
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name = entry.get('name_value', '')
                    
                    # Handle multiple names (newline separated)
                    names = name.split('\n')
                    
                    for domain in names:
                        domain = domain.strip().lower()
                        
                        # Remove wildcards and validate
                        if domain.startswith('*.'):
                            domain = domain[2:]
                        
                        if domain.endswith(self.target) and domain not in self.discovered:
                            try:
                                ip = socket.gethostbyname(domain)
                                self.discovered.add(domain)
                                self._save_subdomain(domain, ip)
                                print(f"    [+] CT Log: {domain} -> {ip}")
                            except socket.gaierror:
                                # Subdomain exists in CT but doesn't resolve
                                self.discovered.add(domain)
                                self._save_subdomain(domain, "unresolved")
                                print(f"    [+] CT Log: {domain} (unresolved)")
                
        except requests.exceptions.RequestException as e:
            print(f"    [-] CT log query failed: {e}")
        except Exception as e:
            print(f"    [-] Error parsing CT logs: {e}")
    
    def _zone_transfer_attempt(self):
        """Attempt DNS zone transfer (usually fails but worth trying)"""
        print("[*] Attempting DNS zone transfer...")
        
        try:
            # First, get name servers
            ns_result = subprocess.run(
                ['nslookup', '-query=ns', self.target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Extract nameservers
            nameservers = []
            for line in ns_result.stdout.split('\n'):
                if 'nameserver' in line.lower():
                    parts = line.split('=')
                    if len(parts) == 2:
                        ns = parts[1].strip().rstrip('.')
                        nameservers.append(ns)
            
            # Try zone transfer on each nameserver
            for ns in nameservers:
                try:
                    zt_result = subprocess.run(
                        ['dig', 'axfr', f'@{ns}', self.target],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if 'Transfer failed' not in zt_result.stdout:
                        print(f"    [!] Zone transfer successful on {ns}!")
                        
                        # Parse results
                        for line in zt_result.stdout.split('\n'):
                            if self.target in line and 'IN' in line:
                                parts = line.split()
                                if len(parts) > 0:
                                    subdomain = parts[0].rstrip('.')
                                    if subdomain.endswith(self.target) and subdomain not in self.discovered:
                                        try:
                                            ip = socket.gethostbyname(subdomain)
                                            self.discovered.add(subdomain)
                                            self._save_subdomain(subdomain, ip)
                                            print(f"    [+] Zone Transfer: {subdomain} -> {ip}")
                                        except:
                                            pass
                    else:
                        print(f"    [-] Zone transfer denied on {ns}")
                        
                except Exception as e:
                    print(f"    [-] Zone transfer failed on {ns}: {e}")
                    
        except FileNotFoundError:
            print("    [-] dig command not found. Install with: apt-get install dnsutils")
        except Exception as e:
            print(f"    [-] Zone transfer attempt failed: {e}")
    
    def _save_subdomain(self, subdomain, ip):
        """Save discovered subdomain to database"""
        finding_data = {
            'subdomain': subdomain,
            'ip_address': ip
        }
        
        finding_id = self.agent.save_finding('subdomains', finding_data)
        
        self.agent.findings['subdomains'].append({
            'id': finding_id,
            'subdomain': subdomain,
            'ip': ip
        })