import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
import json
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set
import pdfkit
import os

# WPScan API Configuration
WPSCAN_API_TOKEN = 'your_api_token_here'  
WPSCAN_API_URL = 'https://wpvulndb.com/api/v3/'

class WordPressSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.vulnerabilities: List[Dict] = []
        self.visited_urls: Set[str] = set()
        self.session = requests.Session()
        colorama.init()

    def crawl(self, url: str, depth: int = 0):
        if depth > self.max_depth or url in self.visited_urls:
            return
        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)
        except Exception as e:
            print(f"Error Crawling {url}: {str(e)}")

    def detect_wordpress_plugins(self, url: str):
        try:
            response = self.session.get(url, verify=False, timeout=5)
            plugins = re.findall(r'/wp-content/plugins/([a-zA-Z0-9-_]+)/', response.text)
            unique_plugins = set(plugins)
            for plugin in unique_plugins:
                self.check_plugin_vulnerabilities(plugin)
        except Exception as e:
            print(f"Error detecting plugins: {str(e)}")

    def check_plugin_vulnerabilities(self, plugin_name: str):
        # Query WPScan API to check for vulnerabilities in the plugin
        try:
            plugin_info = self.get_plugin_info_from_wpscan(plugin_name)
            if plugin_info:
                self.vulnerabilities.append({
                    'type': 'Plugin Vulnerability',
                    'plugin': plugin_name,
                    'description': plugin_info['description'],
                    'url': plugin_info['url']
                })
                print(f"{colorama.Fore.RED}[PLUGIN VULNERABILITY FOUND]{colorama.Style.RESET_ALL}: {plugin_name}")
        except Exception as e:
            print(f"Error checking plugin vulnerabilities: {str(e)}")

    def get_plugin_info_from_wpscan(self, plugin_name: str):
        # Construct URL for WPScan API request
        url = f"{WPSCAN_API_URL}themes/{plugin_name}"
        headers = {
            "Authorization": f"Token token={WPSCAN_API_TOKEN}"
        }
        response = self.session.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # If we find the plugin, return the details
            if data.get("vulnerabilities"):
                vulnerabilities = data["vulnerabilities"]
                latest_vulnerability = vulnerabilities[0]  # Get the most recent vulnerability
                return {
                    'description': latest_vulnerability.get('title', 'No description available'),
                    'url': latest_vulnerability.get('url', 'No URL available')
                }
        return None
    
    def dynamic_analysis(self, url: str):
        """
        Performs dynamic analysis by testing discovered URLs and plugin endpoints
        for runtime vulnerabilities such as SQL injection and insecure endpoints.
        """
        try:
            # First Layer: General SQL Injection testing
            sql_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --"]
            for payload in sql_payloads:
                test_url = f"{url}?test={payload}"
                response = self.session.get(test_url, verify=False, timeout=5)
                if any(error in response.text.lower() for error in ["sql", "mysql", "syntax error", "warning", "unclosed quotation"]):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection (Dynamic)',
                        'url': test_url,
                        'payload': payload
                    })
                    print(f"{colorama.Fore.RED}[DYNAMIC SQL VULNERABILITY]{colorama.Style.RESET_ALL}: {test_url}")

            # Second Layer: Plugin endpoint testing
            plugin_endpoints = [
                "/wp-admin/admin-ajax.php",
                "/wp-json/wp/v2/",
                "/wp-content/plugins/",
            ]
            for endpoint in plugin_endpoints:
                full_url = urllib.parse.urljoin(self.target_url, endpoint)
                response = self.session.get(full_url, verify=False, timeout=5)
                if response.status_code == 200 and "error" in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'Potential Insecure Plugin Endpoint',
                        'url': full_url
                    })
                    print(f"{colorama.Fore.YELLOW}[PLUGIN ENDPOINT WARNING]{colorama.Style.RESET_ALL}: {full_url}")
        except Exception as e:
            print(f"Error during dynamic analysis of {url}: {str(e)}")


    def check_sql_injection(self, url: str):
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--"]
        for payload in sql_payloads:
            try:
                test_url = f"{url}?id={payload}"
                response = self.session.get(test_url)
                if "SQL" in response.text or "mysql" in response.text:
                    self.vulnerabilities.append({'type': 'SQL Injection', 'url': url, 'payload': payload})
            except Exception as e:
                print(f"Error testing SQL Injection: {str(e)}")

    def generate_report(self):
        html_content = f"""
        <html>
        <head><title>WordPress Security Scan Report</title></head>
        <body>
            <h1>Security Scan Report</h1>
            <p>Scanned URL: {self.target_url}</p>
            <p>Total URLs Scanned: {len(self.visited_urls)}</p>
            <p>Vulnerabilities Found: {len(self.vulnerabilities)}</p>
            <h2>Details</h2>
            <ul>
        """
        
        for vuln in self.vulnerabilities:
            html_content += f"""
            <li><b>Type:</b> {vuln['type']}<br>
                <b>Details:</b> {vuln.get('description', vuln.get('plugin', vuln.get('url', '')))}<br>
                <b>Payload:</b> {vuln.get('payload', '')}
            </li>
            """
        
        html_content += "</ul></body></html>"
        with open("scan_report.html", "w") as file:
            file.write(html_content)
        pdfkit.from_file("scan_report.html", "scan_report.pdf")

    def scan(self):
        print(f"\nScanning {self.target_url}...\n")
        self.crawl(self.target_url)
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.detect_wordpress_plugins, url)
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.dynamic_analysis, url)
        self.generate_report()
        print(f"\nScan Complete! {len(self.vulnerabilities)} vulnerabilities found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = WordPressSecurityScanner(target_url)
    scanner.scan()
