import requests
import concurrent.futures
import sys
import time
import argparse
import csv
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def normalize_url(url):
    """Normalize URL to ensure proper format with protocol."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

def check_index_php(url, timeout=10, verify_ssl=False, user_agent=None):
    """
    Check if index.php exists at the given URL with enhanced error handling.
    
    Args:
        url: The website URL to check
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        user_agent: Custom user agent string
        
    Returns:
        dict: Result information including status, message, and response time
    """
    start_time = time.time()
    normalized_url = normalize_url(url)
    target_url = f"{normalized_url}/index.php"
    
    headers = {
        'User-Agent': user_agent or 'IndexChecker/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml',
        'Connection': 'close'  # Don't keep connection alive
    }
    
    try:
        response = requests.get(
            target_url,
            timeout=timeout,
            verify=verify_ssl,
            headers=headers,
            allow_redirects=True
        )
        
        elapsed_time = time.time() - start_time
        status_code = response.status_code
        
        if status_code == 200:
            result = {
                'url': url,
                'status': 'FOUND',
                'code': status_code,
                'time': f"{elapsed_time:.2f}s",
                'message': f"✅ index.php found at: {target_url}"
            }
        else:
            result = {
                'url': url,
                'status': 'NOT_FOUND',
                'code': status_code,
                'time': f"{elapsed_time:.2f}s",
                'message': f"❌ index.php not found (Status: {status_code}): {url}"
            }
            
    except requests.exceptions.Timeout:
        result = {
            'url': url,
            'status': 'TIMEOUT',
            'code': None,
            'time': f"{time.time() - start_time:.2f}s",
            'message': f"⏱️ Timeout while checking {url}"
        }
    except requests.exceptions.SSLError:
        result = {
            'url': url,
            'status': 'SSL_ERROR',
            'code': None,
            'time': f"{time.time() - start_time:.2f}s",
            'message': f"🔒 SSL certificate error for {url}"
        }
    except requests.exceptions.ConnectionError:
        result = {
            'url': url,
            'status': 'CONNECTION_ERROR',
            'code': None,
            'time': f"{time.time() - start_time:.2f}s",
            'message': f"📶 Connection error for {url}"
        }
    except requests.exceptions.MissingSchema:
        result = {
            'url': url,
            'status': 'INVALID_URL',
            'code': None,
            'time': f"{time.time() - start_time:.2f}s",
            'message': f"⚠️ Invalid URL format: {url}"
        }
    except requests.exceptions.RequestException as e:
        result = {
            'url': url,
            'status': 'ERROR',
            'code': None,
            'time': f"{time.time() - start_time:.2f}s",
            'message': f"❗ Error checking {url}: {e}"
        }
            
    return result

def check_websites_for_index_php(websites, workers=10, timeout=10, verify_ssl=False, user_agent=None):
    """
    Check multiple websites for index.php using thread pool.
    
    Args:
        websites: List of website URLs to check
        workers: Number of concurrent worker threads
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        user_agent: Custom user agent string
        
    Returns:
        list: Results for all websites
    """
    results = []
    total = len(websites)
    completed = 0
    
    print(f"Starting scan of {total} websites with {workers} concurrent connections...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_url = {
            executor.submit(
                check_index_php, url, timeout, verify_ssl, user_agent
            ): url for url in websites
        }
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)
                
                # Update progress
                completed += 1
                progress = (completed / total) * 100
                sys.stdout.write(f"\rProgress: [{completed}/{total}] {progress:.1f}% - Checking: {url}")
                sys.stdout.flush()
                
            except Exception as e:
                results.append({
                    'url': url,
                    'status': 'EXCEPTION',
                    'code': None,
                    'time': 'N/A',
                    'message': f"❗ Exception processing {url}: {e}"
                })
                
    print("\nScan completed!")
    return results

def load_urls_from_file(filename):
    """Load URLs from a file, supporting txt, csv formats."""
    urls = []
    
    try:
        file_extension = filename.split('.')[-1].lower()
        
        if file_extension == 'csv':
            with open(filename, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and len(row) > 0 and row[0].strip():
                        urls.append(row[0].strip())
        else:  # Default to txt format
            with open(filename, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):  # Skip comments
                        urls.append(url)
                        
        return urls
    except Exception as e:
        print(f"Error loading URLs from file {filename}: {e}")
        return []

def export_results(results, output_format, filename=None):
    """Export results in the specified format."""
    if output_format == 'csv' and filename:
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Status', 'Status Code', 'Response Time', 'Message'])
                for result in results:
                    writer.writerow([
                        result['url'],
                        result['status'],
                        result['code'],
                        result['time'],
                        result['message']
                    ])
            print(f"Results exported to {filename}")
        except Exception as e:
            print(f"Error exporting results to CSV: {e}")
    else:
        # Print summary statistics
        total = len(results)
        found = sum(1 for r in results if r['status'] == 'FOUND')
        errors = sum(1 for r in results if r['status'] not in ['FOUND', 'NOT_FOUND'])
        
        print(f"\n===== SUMMARY =====")
        print(f"Total websites checked: {total}")
        print(f"index.php found: {found} ({found/total*100:.1f}%)")
        print(f"index.php not found: {total - found - errors} ({(total-found-errors)/total*100:.1f}%)")
        print(f"Errors encountered: {errors} ({errors/total*100:.1f}%)")
        print(f"===================\n")
        
        # Print detailed results
        print("===== DETAILED RESULTS =====")
        for result in results:
            print(result['message'])

def main():
    """Main function to parse arguments and run the scanner."""
    parser = argparse.ArgumentParser(description="Check websites for the presence of index.php")
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-u', '--url', help='Single URL to check')
    input_group.add_argument('-f', '--file', help='File containing URLs (one per line)')
    input_group.add_argument('-l', '--list', nargs='+', help='List of URLs to check')
    
    # Configuration
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--format', choices=['text', 'csv'], default='text', help='Output format (default: text)')
    
    args = parser.parse_args()
    
    # Build list of URLs to check
    websites = []
    if args.url:
        websites = [args.url]
    elif args.file:
        websites = load_urls_from_file(args.file)
    elif args.list:
        websites = args.list
    
    if not websites:
        print("No valid URLs provided. Exiting.")
        return
    
    print(f"Loaded {len(websites)} URLs to check")
    
    # Run the scan
    results = check_websites_for_index_php(
        websites,
        workers=args.workers,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        user_agent=args.user_agent
    )
    
    # Export/display results
    export_results(
        results,
        output_format=args.format,
        filename=args.output
    )

if __name__ == "__main__":
    main()