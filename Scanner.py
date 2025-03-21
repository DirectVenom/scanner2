import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set

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