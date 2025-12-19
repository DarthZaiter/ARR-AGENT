#!/usr/bin/env python3
"""
ML-Based Risk Scoring Module for ARR-Agent
Uses machine learning techniques to score and prioritize findings
"""

import json
import sqlite3
from datetime import datetime

class RiskScorer:
    """ML-based risk scoring engine"""
    
    def __init__(self, agent):
        self.agent = agent
        
        # Risk scoring weights and factors
        self.port_risk_weights = {
            'critical_services': 0.4,
            'version_known': 0.2,
            'common_exploits': 0.3,
            'exposure': 0.1
        }
        
        self.secret_risk_weights = {
            'secret_type': 0.5,
            'exposure_age': 0.2,
            'credential_validity': 0.3
        }
        
        # Known critical services and their base risk scores
        self.critical_services = {
            'ssh': {'score': 7.0, 'reason': 'Remote access - high value target'},
            'rdp': {'score': 8.0, 'reason': 'Remote desktop - critical access'},
            'telnet': {'score': 9.0, 'reason': 'Unencrypted remote access - critical'},
            'ftp': {'score': 6.0, 'reason': 'File transfer - potential data exfiltration'},
            'mysql': {'score': 7.5, 'reason': 'Database access - data exposure'},
            'postgresql': {'score': 7.5, 'reason': 'Database access - data exposure'},
            'mongodb': {'score': 7.0, 'reason': 'Database access - often misconfigured'},
            'redis': {'score': 6.5, 'reason': 'In-memory database - potential data access'},
            'elasticsearch': {'score': 7.0, 'reason': 'Search engine - data exposure'},
            'jenkins': {'score': 8.5, 'reason': 'CI/CD system - code execution possible'},
            'docker': {'score': 8.0, 'reason': 'Container management - lateral movement'},
            'kubernetes': {'score': 9.0, 'reason': 'Orchestration - cluster compromise'},
            'vnc': {'score': 7.5, 'reason': 'Remote desktop - visual access'},
            'smb': {'score': 7.0, 'reason': 'File sharing - lateral movement'},
            'ldap': {'score': 7.5, 'reason': 'Directory service - credential access'},
            'winrm': {'score': 8.0, 'reason': 'Windows remote management'},
        }
        
        # Secret type risk scores
        self.secret_risk_scores = {
            'aws_access_key': 9.0,
            'aws_secret_key': 9.5,
            'github_token': 8.0,
            'private_key': 9.0,
            'api_key': 7.0,
            'password': 7.5,
            'jwt': 6.5,
            'database_url': 8.5,
            'stripe_key': 8.0,
            'slack_token': 6.0
        }
    
    def score_all_findings(self):
        """Score all findings across all modules"""
        print("[*] Scoring port scan findings...")
        self._score_ports()
        
        print("[*] Scoring subdomain findings...")
        self._score_subdomains()
        
        print("[*] Scoring secret findings...")
        self._score_secrets()
        
        print("[*] Generating attack paths...")
        self._generate_attack_paths()
        
        print("[+] Risk scoring complete")
    
    def _score_ports(self):
        """Score open ports based on service criticality"""
        for port_finding in self.agent.findings['ports']:
            service = port_finding.get('service', 'unknown').lower()
            version = port_finding.get('version', '')
            port = port_finding.get('port', 0)
            
            # Base risk score
            risk_score = 5.0
            risk_factors = []
            
            # Check if it's a critical service
            if service in self.critical_services:
                risk_score = self.critical_services[service]['score']
                risk_factors.append(self.critical_services[service]['reason'])
            
            # Version detection bonus (helps identify vulnerabilities)
            if version and version != '':
                risk_factors.append("Version detected - easier to find exploits")
            
            # Common exploit ports
            high_risk_ports = [21, 22, 23, 25, 445, 3389, 5900, 8080]
            if port in high_risk_ports:
                risk_score += 1.0
                risk_factors.append(f"Port {port} commonly targeted")
            
            # Internet-facing exposure
            if port < 1024:
                risk_factors.append("Low port number - likely internet-facing")
            
            # Unencrypted services
            unencrypted = ['telnet', 'ftp', 'http']
            if service in unencrypted:
                risk_score += 1.5
                risk_factors.append("Unencrypted protocol - traffic interception possible")
            
            # Cap at 10.0
            risk_score = min(10.0, risk_score)
            
            # Save risk score
            self._save_risk_score(
                'port',
                port_finding.get('id'),
                risk_score,
                risk_factors
            )
            
            # Determine criticality
            criticality = self._get_criticality(risk_score)
            
            print(f"    [{criticality}] Port {port}/{service}: Risk Score {risk_score:.1f}")
    
    def _score_subdomains(self):
        """Score subdomains based on naming patterns and exposure"""
        for subdomain_finding in self.agent.findings['subdomains']:
            subdomain = subdomain_finding.get('subdomain', '')
            
            risk_score = 3.0  # Base score
            risk_factors = []
            
            # High-value subdomain patterns
            high_value_patterns = [
                'admin', 'api', 'vpn', 'remote', 'portal', 'login',
                'staging', 'dev', 'test', 'internal', 'management',
                'jenkins', 'gitlab', 'jira', 'confluence'
            ]
            
            subdomain_lower = subdomain.lower()
            for pattern in high_value_patterns:
                if pattern in subdomain_lower:
                    risk_score += 2.0
                    risk_factors.append(f"High-value subdomain pattern: {pattern}")
            
            # Development/staging environments (often less secure)
            if any(word in subdomain_lower for word in ['dev', 'test', 'staging', 'beta']):
                risk_score += 1.5
                risk_factors.append("Development environment - potentially weaker security")
            
            # Direct IP resolution
            if subdomain_finding.get('ip') and subdomain_finding['ip'] != 'unresolved':
                risk_factors.append("Subdomain resolves - active target")
            else:
                risk_score -= 1.0
                risk_factors.append("Subdomain does not resolve - lower priority")
            
            risk_score = min(10.0, max(1.0, risk_score))
            
            self._save_risk_score(
                'subdomain',
                subdomain_finding.get('id'),
                risk_score,
                risk_factors
            )
            
            criticality = self._get_criticality(risk_score)
            print(f"    [{criticality}] {subdomain}: Risk Score {risk_score:.1f}")
    
    def _score_secrets(self):
        """Score exposed secrets based on type and exposure"""
        for secret_finding in self.agent.findings['secrets']:
            secret_type = secret_finding.get('type', 'unknown')
            
            # Base risk from secret type
            risk_score = self.secret_risk_scores.get(secret_type, 7.0)
            risk_factors = [f"Exposed {secret_type}"]
            
            # Public GitHub exposure
            if 'repo' in secret_finding:
                risk_score += 1.5
                risk_factors.append("Publicly exposed on GitHub")
            
            # Cloud credentials are critical
            if 'aws' in secret_type or 'azure' in secret_type or 'gcp' in secret_type:
                risk_factors.append("Cloud credential - potential infrastructure access")
            
            # Database credentials
            if 'database' in secret_type or 'mysql' in secret_type:
                risk_factors.append("Database credential - data exposure risk")
            
            risk_score = min(10.0, risk_score)
            
            self._save_risk_score(
                'secret',
                secret_finding.get('id'),
                risk_score,
                risk_factors
            )
            
            criticality = self._get_criticality(risk_score)
            print(f"    [{criticality}] {secret_type}: Risk Score {risk_score:.1f}")
    
    def _generate_attack_paths(self):
        """Correlate findings to identify potential attack paths"""
        print("\n[*] Analyzing attack paths...")
        
        attack_paths = []
        
        # Attack Path 1: Leaked credential + accessible service
        if self.agent.findings['secrets'] and self.agent.findings['ports']:
            for secret in self.agent.findings['secrets']:
                for port in self.agent.findings['ports']:
                    service = port.get('service', '').lower()
                    
                    # Match credential type to service
                    if 'ssh' in service and 'private_key' in secret.get('type', ''):
                        attack_paths.append({
                            'path': 'SSH Access via Leaked Private Key',
                            'risk': 9.5,
                            'steps': [
                                f"1. Private key found: {secret.get('repo', 'Unknown source')}",
                                f"2. SSH service open on port {port.get('port')}",
                                f"3. Potential remote access to {port.get('host')}"
                            ]
                        })
                    
                    if 'database' in service and 'password' in secret.get('type', ''):
                        attack_paths.append({
                            'path': 'Database Access via Leaked Credentials',
                            'risk': 9.0,
                            'steps': [
                                f"1. Database credentials found",
                                f"2. {service} service open on port {port.get('port')}",
                                f"3. Potential data exfiltration from {port.get('host')}"
                            ]
                        })
        
        # Attack Path 2: Subdomain + Open ports = Entry point
        if self.agent.findings['subdomains'] and self.agent.findings['ports']:
            dev_subdomains = [s for s in self.agent.findings['subdomains'] 
                            if any(word in s.get('subdomain', '').lower() 
                                   for word in ['dev', 'test', 'staging'])]
            
            if dev_subdomains:
                attack_paths.append({
                    'path': 'Development Environment Exploitation',
                    'risk': 8.0,
                    'steps': [
                        f"1. Development subdomains discovered: {len(dev_subdomains)} found",
                        f"2. Services exposed: {len(self.agent.findings['ports'])} ports open",
                        "3. Dev environments often have weaker security",
                        "4. Potential lateral movement to production"
                    ]
                })
        
        # Store attack paths
        for path in attack_paths:
            print(f"\n    [!] ATTACK PATH IDENTIFIED:")
            print(f"        {path['path']} (Risk: {path['risk']}/10)")
            for step in path['steps']:
                print(f"        {step}")
        
        self.agent.findings['attack_paths'] = attack_paths
    
    def _save_risk_score(self, finding_type, finding_id, risk_score, risk_factors):
        """Save risk score to database"""
        risk_data = {
            'finding_type': finding_type,
            'finding_id': finding_id,
            'risk_score': risk_score,
            'risk_factors': json.dumps(risk_factors)
        }
        
        self.agent.save_finding('risk_scores', risk_data)
        
        # Add to findings
        if 'risks' not in self.agent.findings:
            self.agent.findings['risks'] = []
        
        self.agent.findings['risks'].append({
            'type': finding_type,
            'id': finding_id,
            'score': risk_score,
            'factors': risk_factors
        })
    
    def _get_criticality(self, risk_score):
        """Convert risk score to criticality level"""
        if risk_score >= 9.0:
            return "CRITICAL"
        elif risk_score >= 7.0:
            return "HIGH"
        elif risk_score >= 5.0:
            return "MEDIUM"
        else:
            return "LOW"