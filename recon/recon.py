"""
What this file does:
  1. fingerprint_target(url)  Looks at the HTTP headers and the HTML of ONE page
                              to guess which server / language the site uses.
                              
  2. crawl_endpoints(url)     Starts at the home page, follows links that stay on
                              the SAME website, and collects every page it can
                              reach plus every form / ?name=value input it finds.
                              
  3. run(url)                 Calls the two steps above and returns ONE dictionary
                              that the other modules (SQLi, XSS, Misconfig) read.

Output shape of run():
  {
    "tech_stack": {"server": "...", "powered_by": "...", "cms_or_generator": "..."},
    "endpoints":  ["https://site.com/", "https://site.com/login", ...],
    "params":     [{"url": "...", "method": "GET" or "POST", "params": ["name", ...]}]
  }
"""

import os
import time
import requests
from bs4 import BeautifulSoup
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs
from dotenv import load_dotenv

load_dotenv()  # reads TARGET_URL from the .env file in this folder (.env is never committed)

TARGET_URL = os.getenv("TARGET_URL")

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
}

DELAY_SECONDS = 1
NOT_FOUND_CODES = (404, 410)


def fingerprint_target(url):
    """
    Step 1: guess the technology from ONE request.
    Reads the response headers (Server, X-Powered-By), cookie names
    (PHPSESSID = PHP, JSESSIONID = Java, ...) and the <meta name="generator"> tag.
    """
    print(f"[*] Fingerprinting target: {url}")
    tech_stack = {}

    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        headers = response.headers
        cookies = response.cookies.get_dict()

        if 'Server' in headers:
            tech_stack['server'] = headers['Server']
        if 'X-Powered-By' in headers:
            tech_stack['powered_by'] = headers['X-Powered-By']

        if 'PHPSESSID' in cookies:
            tech_stack['language'] = 'PHP'
        elif 'laravel_session' in cookies:
            tech_stack['framework'] = 'Laravel'
        elif 'JSESSIONID' in cookies:
            tech_stack['language'] = 'Java'

        soup = BeautifulSoup(response.text, 'html.parser')
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            tech_stack['cms_or_generator'] = generator['content']

        return tech_stack

    except requests.exceptions.RequestException as e:
        print(f"[!] Fingerprinting connection error: {e}")
        return {"error": "Target unreachable"}


def extract_params(soup, current_url):
    """
    find every <form> on ONE page and list the field names inside it.

    Returns a list such as:
      [{"url": "https://site.com/login", "method": "POST",
        "params": ["username", "password"]}]
    """
    forms_data = []

    for form in soup.find_all("form"):
        method = (form.get("method") or "get").strip().upper()
        action = form.get("action", "")
        form_url = urljoin(current_url, action)

        # textarea is included on purpose: XSS testing needs every text box
        names = [
            field.get("name")
            for field in form.find_all(["input", "textarea", "select"])
            if field.get("name")
        ]
        names = list(dict.fromkeys(names))

        if names:
            forms_data.append({"url": form_url, "method": method, "params": names})

    return forms_data


def _remove_duplicate_params(params_list):
    """
    Helper: the same form can appear on many pages (for example a search box in
    the header). Keep only one copy of each (url + method + param names).
    """
    seen = set()
    unique = []
    for item in params_list:
        key = (item["url"], item["method"], tuple(item["params"]))  # tuple: sets only accept unchangeable items fa mynf34 n use list
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def crawl_endpoints(start_url, max_depth=2, max_pages=100):
    """
    Step 2: a BFS crawl (visit pages level by level).

      queue    = pages still waiting to be visited. We take from the FRONT (popleft)
                 and add to the BACK (append), so pages are visited in order.
      visited  = a set of every URL we have already queued, so we never visit one twice.
      depth    = how many clicks away from the start page a page is (start = 0).
    """
    if urlparse(start_url).path == "":
        start_url = start_url + "/"

    queue = deque([(start_url, 0)])
    visited = {start_url}
    scan_results = {
        "endpoints": [],
        "params": []
    }

    target_domain = urlparse(start_url).netloc  # scope: only this website is crawled

    while queue:
        if len(visited) >= max_pages:  # safety limit against endless pagination or filter pages
            print(f"[!] Reached MAX_PAGES limit ({max_pages}), stopping crawl.")
            break

        current_url, depth = queue.popleft()
        print(f"[*] Crawling: {current_url} (Depth: {depth})")

        try:
            response = requests.get(current_url, headers=HEADERS, timeout=10)
            final_url = response.url  # the address after any redirects

            if urlparse(final_url).netloc != target_domain:  # a redirect left the target: out of scope
                print(f"[!] Redirected off the target to {final_url}, skipping.")
                continue

            if response.status_code in NOT_FOUND_CODES:  # a 404 is not a real endpoint
                print(f"[!] Not found ({response.status_code}), skipping: {final_url}")
                continue

            scan_results["endpoints"].append(final_url)

            parsed_final = urlparse(final_url)
            if parsed_final.query:
                query_names = list(parse_qs(parsed_final.query).keys())
                base_url = f"{parsed_final.scheme}://{parsed_final.netloc}{parsed_final.path}"
                scan_results["params"].append({
                    "url": base_url,
                    "method": "GET",
                    "params": query_names
                })

            if 'text/html' not in response.headers.get('Content-Type', ''):  # PDFs, images, etc. have no forms fa we skip
                continue

            soup = BeautifulSoup(response.text, 'html.parser')
            scan_results["params"].extend(extract_params(soup, final_url))

            if depth >= max_depth:
                continue

            extracted_links = [
                a["href"].strip()
                for a in soup.find_all("a", href=True)
                if a["href"].strip()
            ]

            for link in extracted_links:
                full_url = urljoin(final_url, link)
                parsed_link = urlparse(full_url)

                if parsed_link.scheme not in ('http', 'https'):  # skip mailto:, javascript:, tel:
                    continue

                if parsed_link.netloc != target_domain:  # never follow links to other websites
                    continue

                clean_url = full_url.split('#')[0]  # "/page#top" and "/page" are the same page

                if clean_url not in visited:
                    visited.add(clean_url)
                    queue.append((clean_url, depth + 1))

        except requests.exceptions.RequestException as e:
            print(f"[!] Network error on {current_url}: {e}")

        finally:
            time.sleep(DELAY_SECONDS)

    scan_results["endpoints"] = list(dict.fromkeys(scan_results["endpoints"]))
    scan_results["params"] = _remove_duplicate_params(scan_results["params"])

    return scan_results


def run(target_url):
    """
    runs fingerprinting and crawling, then returns the final result.
    This is the function the FastAPI backend will call.
    """
    print(f"\nStarting Recon Module against {target_url}")

    tech_stack = fingerprint_target(target_url)
    crawl_data = crawl_endpoints(target_url)

    return {
        "tech_stack": tech_stack,
        "endpoints": crawl_data["endpoints"],
        "params": crawl_data["params"]
    }


if __name__ == "__main__":  # runs only when started directly (python recon.py), not when imported
    if not TARGET_URL:
        print("[!] ERROR: TARGET_URL is not set. Check your .env file.")
    else:
        final_output = run(TARGET_URL)
        print("\nFINAL RECON JSON OUTPUT")
        print(final_output)