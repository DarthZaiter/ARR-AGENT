#!/usr/bin/env python3
"""
Port Scanner Module for ARR-Agent
Integrates with nmap for comprehensive port scanning
"""

import subprocess
import xml.etree.ElementTree as ET
import json
from pathlib import Path

class PortScanner:
    """Port scanning module using nmap"""
    
    def __init__(self, agent):
        self.agent = agent
        self.target = agent.target
    
    def check_nmap_installed(self):
        """Check if nmap is installed"""
        try:
            subprocess.run(['nmap', '--version'], 
                         capture_output=True, 
                         check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def scan(self, ports="1-65535", scan_type="full"):
        """
        Perform port scan on target
        
        Args:
            ports: Port range to scan (default: 1-65535 - all ports)
            scan_type: 'fast', 'full', or 'custom'
        """
        print(f"[*] Starting FULL port scan on {self.target} (ports 1-65535)")
        print(f"[*] Note: Full port scan may take 5-15 minutes depending on network speed")
        
        if not self.check_nmap_installed():
            print("[-] nmap not found. Falling back to basic TCP connect scan...")
            self._fallback_scan(ports)
            return
        
        # Configure nmap command based on scan type
        if scan_type == "fast":
            # Fast mode still scans common ports but more aggressively
            nmap_args = ['-sV', '-T4', '--top-ports', '1000']
            print(f"[*] Fast mode: Scanning top 1000 ports only")
        elif scan_type == "full":
            # Full comprehensive scan - all 65535 ports with service detection
            nmap_args = ['-sV', '-T4', '-p-']
            print(f"[*] Full mode: Scanning ALL 65535 ports")
        else:
            nmap_args = ['-sV', '-T4', '-p', ports]
        
        # Output file for XML results
        output_file = self.agent.output_dir / f"nmap_{self.agent.session_id}.xml"
        
        # Build nmap command
        cmd = ['nmap'] + nmap_args + ['-oX', str(output_file), self.target]
        
        print(f"[*] Running: {' '.join(cmd)}")
        
        try:
            # Run nmap
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=1800)  # 30 minute timeout for full scan
            
            if result.returncode != 0:
                print(f"[-] nmap error: {result.stderr}")
                return
            
            # Parse results
            self._parse_nmap_xml(output_file)
            
        except subprocess.TimeoutExpired:
            print("[-] Scan timeout after 30 minutes")
        except Exception as e:
            print(f"[-] Scan error: {e}")
    
    def _parse_nmap_xml(self, xml_file):
        """Parse nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            total_ports = 0
            
            for host in root.findall('host'):
                # Get host address
                address = host.find('address').get('addr')
                
                # Get hostname if available
                hostnames = host.find('hostnames')
                hostname = None
                if hostnames is not None:
                    hostname_elem = hostnames.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')
                
                # Parse ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        
                        state = port.find('state')
                        state_val = state.get('state') if state is not None else 'unknown'
                        
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        service_version = service.get('version') if service is not None else ''
                        
                        # Store in database
                        finding_data = {
                            'host': hostname or address,
                            'port': int(port_id),
                            'protocol': protocol,
                            'state': state_val,
                            'service': service_name,
                            'version': service_version
                        }
                        
                        finding_id = self.agent.save_finding('ports', finding_data)
                        
                        # Add to in-memory findings
                        self.agent.findings['ports'].append({
                            'id': finding_id,
                            **finding_data
                        })
                        
                        total_ports += 1
                        
                        print(f"    [+] Found: {address}:{port_id}/{protocol} - {service_name} {service_version} ({state_val})")
            
            print(f"[+] Port scan complete. Found {total_ports} open ports")
            
        except Exception as e:
            print(f"[-] Error parsing nmap output: {e}")
    
    def _fallback_scan(self, ports):
        """Fallback basic TCP connect scan if nmap not available"""
        import socket
        
        print(f"[*] Running basic TCP connect scan on common high-risk ports...")
        print(f"[!] WARNING: Without nmap, only scanning ~200 common ports")
        print(f"[!] Install nmap for full 65535 port coverage")
        
        # Extended common ports list including high ports for remote admin
        common_ports = [
            # Standard services (1-1024)
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
            # Common application ports (1025-10000)
            1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 5432, 5900, 5985, 5986,
            6379, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300,
            # High ports often used for remote admin (10000-65535)
            10000, 27017, 27018, 50000, 50070, 50075, 55553, 55554
        ]
        
        open_ports = []
        total_ports = len(common_ports)
        
        print(f"[*] Testing {total_ports} high-risk ports...")
        
        for i, port in enumerate(common_ports, 1):
            if i % 20 == 0:
                print(f"[*] Progress: {i}/{total_ports} ports tested...")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                open_ports.append(port)
                
                # Store in database
                finding_data = {
                    'host': self.target,
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': 'unknown',
                    'version': ''
                }
                
                finding_id = self.agent.save_finding('ports', finding_data)
                
                self.agent.findings['ports'].append({
                    'id': finding_id,
                    **finding_data
                })
                
                print(f"    [+] Port {port}/tcp is open")
            
            sock.close()
        
        print(f"[+] Basic scan complete. Found {len(open_ports)} open ports")
        print(f"[!] For comprehensive results, install nmap to scan all 65535 ports")