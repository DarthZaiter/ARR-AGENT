#!/usr/bin/env python3
"""
GitHub Secret Scanner Module for ARR-Agent
Searches for exposed secrets in public GitHub repositories
"""

import re
import requests
import time
from urllib.parse import quote

class GitHubSecretScanner:
    """GitHub secret scanning module"""
    
    def __init__(self, agent):
        self.agent = agent
        self.target = agent.target
        self.github_token = None  # Optional: Set GitHub API token for higher rate limits
        
        # Secret patterns to detect
        self.patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]',
            'github_token': r'ghp_[0-9a-zA-Z]{36}',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
            'private_key': r'-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----',
            'api_key': r'(?i)(api[_-]?key|apikey)[\s]*[=:]+[\s]*[\'"]?([0-9a-zA-Z\-_]{20,})[\'"]?',
            'password': r'(?i)(password|passwd|pwd)[\s]*[=:]+[\s]*[\'"]?([^\s\'\"]{8,})[\'"]?',
            'jwt': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'database_url': r'(?i)(mysql|postgres|mongodb):\/\/[^\s]+',
            'stripe_key': r'(?i)(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}',
            'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
            'mailgun_api': r'key-[0-9a-zA-Z]{32}',
            'twilio_api': r'SK[0-9a-fA-F]{32}'
        }
    
    def scan(self):
        """Scan GitHub for secrets related to target"""
        print(f"[*] Scanning GitHub for exposed secrets related to {self.target}")
        
        # Search queries to run
        search_queries = [
            self.target,
            f'"{self.target}" password',
            f'"{self.target}" api_key',
            f'"{self.target}" credentials',
            f'"{self.target}" token',
            f'"{self.target}" secret',
            f'"{self.target}" aws_access_key_id',
            f'"{self.target}" private_key'
        ]
        
        total_secrets = 0
        
        for query in search_queries:
            print(f"[*] Searching: {query}")
            secrets = self._search_github(query)
            total_secrets += len(secrets)
            time.sleep(2)  # Rate limiting
        
        print(f"[+] GitHub scan complete. Found {total_secrets} potential secrets")
    
    def _search_github(self, query):
        """Search GitHub code for query"""
        secrets_found = []
        
        try:
            # GitHub Code Search API
            url = f"https://api.github.com/search/code?q={quote(query)}&per_page=30"
            
            headers = {
                'Accept': 'application/vnd.github.v3+json'
            }
            
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 403:
                print("    [-] GitHub API rate limit exceeded. Set GITHUB_TOKEN for higher limits.")
                return secrets_found
            
            if response.status_code != 200:
                print(f"    [-] GitHub search failed: {response.status_code}")
                return secrets_found
            
            data = response.json()
            
            if 'items' not in data:
                return secrets_found
            
            # Process each result
            for item in data['items'][:10]:  # Limit to first 10 results
                repo_name = item['repository']['full_name']
                file_path = item['path']
                html_url = item['html_url']
                
                # Get file content
                content = self._get_file_content(item.get('url'))
                
                if content:
                    # Scan content for secrets
                    found_secrets = self._scan_content(content, repo_name, file_path, html_url)
                    secrets_found.extend(found_secrets)
                
                time.sleep(1)  # Rate limiting
            
        except requests.exceptions.RequestException as e:
            print(f"    [-] GitHub API error: {e}")
        except Exception as e:
            print(f"    [-] Error during GitHub scan: {e}")
        
        return secrets_found
    
    def _get_file_content(self, url):
        """Get raw file content from GitHub"""
        try:
            headers = {
                'Accept': 'application/vnd.github.v3.raw'
            }
            
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                return response.text
            
        except Exception as e:
            print(f"    [-] Failed to get file content: {e}")
        
        return None
    
    def _scan_content(self, content, repo, file_path, url):
        """Scan content for secret patterns"""
        found_secrets = []
        
        for secret_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, content)
            
            for match in matches:
                secret_value = match.group(0)
                
                # Get context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end]
                
                # Save finding
                finding_data = {
                    'source': f"{repo}/{file_path}",
                    'secret_type': secret_type,
                    'value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                    'context': context.replace('\n', ' ')
                }
                
                finding_id = self.agent.save_finding('secrets', finding_data)
                
                self.agent.findings['secrets'].append({
                    'id': finding_id,
                    'repo': repo,
                    'file': file_path,
                    'type': secret_type,
                    'url': url,
                    'value': secret_value
                })
                
                found_secrets.append(finding_data)
                
                print(f"    [!] FOUND {secret_type.upper()}: {repo}/{file_path}")
                print(f"        URL: {url}")
                print(f"        Value: {secret_value[:30]}...")
        
        return found_secrets
    
    def set_github_token(self, token):
        """Set GitHub API token for authenticated requests"""
        self.github_token = token