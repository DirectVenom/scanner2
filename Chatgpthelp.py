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
        try:
            with open("wordpress_vuln_db.json", "r") as file:
                vuln_db = json.load(file)
            
            if plugin_name in vuln_db:
                self.vulnerabilities.append({
                    'type': 'Plugin Vulnerability',
                    'plugin': plugin_name,
                    'description': vuln_db[plugin_name]
                })
                print(f"{colorama.Fore.RED}[PLUGIN VULNERABILITY FOUND]{colorama.Style.RESET_ALL}: {plugin_name}")
        except Exception as e:
            print(f"Error checking plugin vulnerabilities: {str(e)}")

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
        self.generate_report()
        print(f"\nScan Complete! {len(self.vulnerabilities)} vulnerabilities found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = WordPressSecurityScanner(target_url)
    scanner.scan()