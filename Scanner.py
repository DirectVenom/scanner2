import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set
from jinja2 import Template
import pdfkit
import argparse

class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        """
        Initialize the security scanner with a target URL and maximum crawl depth.

        Args:
            target_url: The base URL to scan
            max_depth: Maximum depth for crawling links (default: 3)
        """
        self.target_url = target_url
        self.max_depth = max_depth
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()

        # Initialize colorama for cross-platform colored output
        colorama.init()
    # implemeting the crawler that will discover pages and URLs in a given target application.
    def crawl(self, url: str, depth: int = 0) -> None:
        # crawl the website to discover pages.
        #arguments: Url - current URL to crawl, Depth - current depth in crawl tree.
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)
        
        except Exception as e:
            print(f"Error Crawling {url}: {str(e)}")
    

    # SQL Injection Detection Check
    def check_sql_injection(self, url: str) -> None:
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        for payload in sql_payloads:
            try:
                Parsed = urllib.pasrse.urlparse(url)
                params = urllib.parse_qs(parsed_query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = self.session.get(test_url)

                    #Looking for SQL error messages
                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.report_vulnerability({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })
            except Exception as e:
                print(f"Error testing SQL injection on {url}: {str(e)}")
    # Cross-site Scripting Check
    
    def check_xss(self, url: str) -> None:
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS)"
        ]

        for payload in xss_payloads:
            try:
                parsed = urllib.parse.urlparsse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", 
                                 f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url)

                    if payload in response.text:
                        self.report_vulnerability({
                         'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })

            except Exception as e:
                print(f"Error testing XSS on {url}: {str(e)}")

    def check_directory_traversal(self, url: str) -> None:
        #Check for Directory Traversal vulnerabilities.
        traversal_payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]

        for payload in traversal_payloads:
            try:
                test_url = url + payload
                response = self.session.get(test_url, timeout=5)

                if "root:x:" in response.text or "[fonts]" in response.text:
                    self.report_vulnerability({
                        'type': 'Directory Traversal',
                        'url': test_url,
                        'payload': payload
                    })
            except requests.RequestException as e:
                print(f"Error testing Directory Traversal on {url}: {str(e)}")

    from jinja2 import Template
import pdfkit

def generate_report(self):
    """Generate an HTML & PDF report of vulnerabilities."""
    template = Template("""
    <html>
    <head><title>Security Scan Report</title></head>
    <body>
        <h1>Security Scan Report</h1>
        <p>Scanned URL: {{ target_url }}</p>
        <p>Total URLs Scanned: {{ total_urls }}</p>
        <p>Vulnerabilities Found: {{ vulnerabilities | length }}</p>
        <hr>
        <h2>Vulnerability Details</h2>
        <ul>
        {% for vuln in vulnerabilities %}
            <li><b>Type:</b> {{ vuln.type }} <br>
                <b>URL:</b> {{ vuln.url }} <br>
                <b>Description:</b> {{ vuln.get('description', '') }} <br>
                <b>Payload:</b> {{ vuln.get('payload', '') }}
            </li>
        {% endfor %}
        </ul>
    </body>
    </html>
    """)

    report_html = template.render(target_url=self.target_url,
                                  total_urls=len(self.visited_urls),
                                  vulnerabilities=self.vulnerabilities)

    with open("scan_report.html", "w") as file:
        file.write(report_html)

    # Convert HTML to PDF
    pdfkit.from_file("scan_report.html", "scan_report.pdf")


    # Main scanner logic 
    def scan(self) -> List[Dict]:
        print(f"\n{colorama,Fore.BLUE} {self.target_url}{colorama.style.RESET_ALL}\n")

        self.crawl(self.target_url) # Crawling the website
        with ThreadPoolExecutor(max_workers=5) as excutor: # Running securtity checks on Urls.
            for url in self.visited_urls:
                excutor.submit(self.check_sql_injection, url)
                excutor.submit(self.check_xss, url)
                excutor.submit(self.check_directory_traversal, url)
                

            
        return self.vulnerabilities
    
    def report_vulnerability(self, vulnerability: Dict) -> None:
        self.vulnerabilities.append(vulnerability)
        print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL}")
        for key, value in vulnerability.items():
            print(f"{key}: {value}")
            print()

    if __name__ == "__main__":
        if len(sys.argv) != 2:
            print("Usage: python scanner.py <target_url>")
            sys.exit(1)

        target_url = sys.argv[1]
        scanner = WebSecurityScanner(target_url)
        vulnerabilites = scanner.scan()


        print(f"\n{colorama.Fore.GREEN}Scan Complete!{colorama.Style.RESET_ALL}")
        print(f"Total URLs scanned: {len(scanner.visited_urls)}")
        print(f"Vulnerabilities found: {len(vulnerabilities)}")
