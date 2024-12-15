import requests
import sys
import os
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
import re
import subprocess
import time

def print_banner():
    banner = """
=============================================
    Advanced Open Redirect Finder | by Karthik S Sathyan
=============================================
"""
    print(colored(banner, "cyan"))

def check_redirect(base_url, payload):
    """Checks if a payload causes an open redirect vulnerability."""
    try:
        test_url = urljoin(base_url, payload)
        print(colored(f"[*] Checking URL: {test_url}", "blue"))
        response = requests.get(test_url, allow_redirects=True, timeout=5)

        status_code = response.status_code
        status_message = f"[*] Response Status Code: {status_code}"
        if status_code == 200:
            status_message = status_message.replace("200", colored("200", "red"))
        print(colored(status_message, "blue"))

        if response.history:
            locations = " --> ".join(str(r.url) for r in response.history)
            print(colored(f"[*] Redirect chain: {locations}", "blue"))
            final_url = response.url
            if "google.com" in final_url:
                print(colored(f"[+] Vulnerability detected: {test_url}", "red"))
                print(colored(f"[+] Verified: {final_url} ✔️", "green"))
                return True, final_url
        return False, None
    except Exception as e:
        print(colored(f"[!] Error checking redirect: {e}", "yellow"))
        return False, str(e)

def load_payloads(file_path):
    """Loads payloads from a file."""
    payloads = []
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            payloads = [line.strip() for line in f.readlines() if line.strip()]
    return payloads

def collect_urls_from_wayback(domain):
    """Collects URLs from Wayback Machine and filters them for open redirect parameters."""
    try:
        # Remove protocol from the domain
        domain = re.sub(r'https?://', '', domain)
        print(colored(f"[*] Running waybackurls for domain: {domain}", "cyan"))

        # Start the waybackurls command with a 10-minute timeout
        start_time = time.time()
        process = subprocess.Popen(["waybackurls", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check if the process has completed within 60 seconds
        while True:
            if process.poll() is not None:
                break
            if time.time() - start_time >= 60:
                print(colored("[*] This might take some time due to the size of the website or internet connection issues.", "yellow"))
                break
            time.sleep(1)

        # Wait for the process to complete or timeout after 10 minutes
        try:
            stdout, stderr = process.communicate(timeout=600)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            print(colored(f"[!] waybackurls command timed out after 10 minutes.", "yellow"))

        print(colored(f"[*] waybackurls command output: {stdout}", "cyan"))

        urls = stdout.splitlines()

        # Filter URLs to keep only those with relevant parameters
        filtered_urls = {}
        for url in urls:
            parsed_url = urlparse(url)
            parameters = re.findall(r'(\w+)=', parsed_url.query)
            for param in parameters:
                if param in ["redirect", "url", "next", "continue", "page"]:
                    if param not in filtered_urls:
                        filtered_urls[param] = []
                    if len(filtered_urls[param]) < 2:  # Keep only 1 or 2 URLs per parameter
                        filtered_urls[param].append(url)

        # Flatten the filtered URLs list
        filtered_urls_list = [url for sublist in filtered_urls.values() for url in sublist]
        return filtered_urls_list
    except Exception as e:
        print(colored(f"[!] Error collecting URLs from Wayback Machine: {e}", "yellow"))
        return []

def extract_parameters(url):
    """Extracts all parameters from the given URL."""
    parsed_url = urlparse(url)
    parameters = re.findall(r'(\w+)=', parsed_url.query)
    return parameters

def main():
    print_banner()
    try:
        domain = input("[*] Enter domain name (e.g., example.com): ").strip()
        if not domain:
            print(colored("[!] Domain name is required.", "red"))
            sys.exit(1)

        print("[*] Collecting URLs from Wayback Machine...")
        urls = collect_urls_from_wayback(domain)
        if not urls:
            print(colored("[!] No URLs found on the domain.", "red"))
            sys.exit(1)

        save_location = input("[*] Enter the location to save the filtered URLs (e.g., /home/kali/Documents/openredirects/urls.txt): ").strip()
        if not save_location:
            print(colored("[!] Save location is required.", "red"))
            sys.exit(1)

        with open(save_location, "w") as f:
            for url in urls:
                f.write(f"{url}\n")
        print(colored(f"[*] Filtered URLs saved to {save_location}", "green"))

        payload_file = "openredirectPayloads.txt"
        payloads = load_payloads(payload_file)
        if not payloads:
            print(colored(f"[!] No payloads found in {payload_file}.", "red"))
            sys.exit(1)

        print(colored("[*] Starting testing with payloads...", "cyan"))
        results = []

        def process_url(url):
            parameters = extract_parameters(url)
            for param in parameters:
                for payload in payloads:
                    test_url = url.replace(f"{param}=", f"{param}={payload}")
                    print(colored(f"[*] Testing: {test_url}", "blue"))
                    is_vulnerable, location = check_redirect(test_url, payload)
                    if is_vulnerable:
                        results.append((test_url, payload, location))

        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(process_url, urls)

        if results:
            with open("results.txt", "w") as out:
                for url, payload, location in results:
                    out.write(f"URL: {url}\nPayload: {payload}\nRedirect: {location}\n\n")
            print(colored("[*] Results are saved in 'results.txt'", "green"))
        else:
            print(colored("[*] No vulnerabilities found.", "green"))

    except KeyboardInterrupt:
        print(colored("\n[!] Stopped by user.", "yellow"))
        sys.exit(1)

if __name__ == "__main__":
    main()
