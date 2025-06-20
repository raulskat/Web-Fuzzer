# src/fuzzing/parameters.py
import asyncio
import json
import os
import re
from urllib.parse import urlparse, urlencode, parse_qs
import time

from src.utils.request_handler import AsyncRequestHandler

class ParameterFuzzer:
    """Fuzzer for testing URL parameters."""
    
    def __init__(self, target_url, async_requests=10, timeout=5, request_delay=0.1, max_depth=3, verify_ssl=True, payloads_file=None):
        """Initialize the parameter fuzzer.
        
        Args:
            target_url (str): The target URL to fuzz
            async_requests (int): Maximum number of concurrent requests
            timeout (int): Request timeout in seconds
            request_delay (float): Delay between requests in seconds
            max_depth (int): Maximum recursion depth for nested parameters
            verify_ssl (bool): Whether to verify SSL certificates
            payloads_file (str): Path to a custom payloads file
        """
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.async_requests = async_requests
        self.timeout = timeout
        self.request_delay = request_delay
        self.max_depth = max_depth
        self.verify_ssl = verify_ssl
        self.results = []
        self.payloads = []  # Changed to empty list instead of empty dict
        self.custom_payloads_file = payloads_file
        self.request_handler = AsyncRequestHandler(ssl_verify=verify_ssl, timeout=timeout)
        self.semaphore = asyncio.Semaphore(async_requests)
        self.progress_callback = None
        self.total_tests = 0
        self.completed_tests = 0
        
        print(f"Starting parameter fuzzing for: {target_url}")

    def load_payloads(self):
        """Load payloads from files or return defaults if not available"""
        default_payloads = [
            ("sql", "' OR '1'='1"),
            ("sql", "1' OR '1'='1' --"),
            ("sql", "1' OR '1'='1' #"),
            ("sql", "' UNION SELECT 1,2,3 --"),
            ("sql", "1; DROP TABLE users"),
            ("sql", "1 UNION SELECT username,password FROM users"),
            ("xss", "<script>alert(1)</script>"),
            ("xss", "<img src=x onerror=alert(1)>"),
            ("xss", "javascript:alert(1)"),
            ("xss", "'-alert(1)-'"),
            ("xss", "\"><script>alert(1)</script>"),
            ("path", "../../../etc/passwd"),
            ("path", "../../../../../../windows/system32/drivers/etc/hosts"),
            ("path", "file:///etc/passwd"),
            ("injection", "admin"),
            ("injection", "admin' --"),
            ("injection", "; ls -la"),
            ("injection", "$(cat /etc/passwd)"),
            ("injection", "`cat /etc/passwd`"),
            ("nosql", "{'$gt': ''}"),
            ("nosql", "[$ne]=1"),
            ("ssti", "{{7*7}}"),
            ("ssti", "${7*7}"),
            ("ssti", "<%= 7*7 %>"),
            ("xxe", "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>"),
            ("ldap", "*)(|(password=*)"),
            ("special", "true"),
            ("special", "false"),
            ("special", "null"),
            ("special", "undefined")
        ]
            
        if not self.custom_payloads_file:
            self.payloads = default_payloads
        else:
            try:
                with open(self.custom_payloads_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            category, payload = line.split(" ", 1)
                            self.payloads.append((category, payload))
            except Exception as e:
                print(f"Error loading {self.custom_payloads_file}: {str(e)}")
                self.payloads = default_payloads
                
        if not self.payloads:
            print("No payloads found. Using default payloads.")
            self.payloads = default_payloads
            
        print(f"Loaded {len(self.payloads)} payloads across multiple categories")

    def extract_params_from_url(self, url):
        """Extract parameters from both the query string and fragment"""
        params = {}
        
        # Parse the URL
        parsed = urlparse(url)
        
        # Extract query parameters
        if parsed.query:
            query_params = parse_qs(parsed.query)
            # Convert from lists to single values
            for key, value in query_params.items():
                params[key] = value[0] if value else ""
        
        # Check if there's a fragment and if it contains parameters
        if parsed.fragment and '?' in parsed.fragment:
            fragment_parts = parsed.fragment.split('?', 1)
            if len(fragment_parts) > 1:
                fragment_query = fragment_parts[1]
                fragment_params = parse_qs(fragment_query)
                # Add fragment parameters
                for key, value in fragment_params.items():
                    params[key] = value[0] if value else ""
        
        return params

    def generate_urls(self, payloads):
        """Generate URLs with payloads for each parameter"""
        parsed = urlparse(self.target_url)
        
        # Determine the base URL without query or fragment
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Extract parameters from both query string and fragment
        params = self.extract_params_from_url(self.target_url)
        
        # For SPAs, determine if parameters are in fragment
        is_fragment_based = parsed.fragment and '?' in parsed.fragment
        
        # If no parameters found, try some common ones
        if not params:
            print(f"No parameters found in URL: {self.target_url}")
            print("Testing with common parameter names...")
            common_params = ['id', 'page', 'search', 'q', 'query', 'name', 'user', 'key', 'token', 'file']
            
            urls = []
            for param in common_params:
                for category, payload in payloads:
                    if is_fragment_based:
                        # For fragment-based URLs (like SPAs)
                        frag_base = parsed.fragment.split('?')[0]
                        fuzzed_url = f"{base}#{frag_base}?{param}={payload}"
                    else:
                        # For regular URLs
                        fuzzed_url = f"{base}?{param}={payload}"
                    urls.append((fuzzed_url, param, payload, category))
            
            print(f"Generated {len(urls)} test URLs with common parameters")
            return urls
        
        # Generate URLs for each parameter and payload
        urls = []
        for param, value in params.items():
            for category, payload in payloads:
                # Create a copy of the parameters and replace the target parameter
                test_params = params.copy()
                test_params[param] = payload
                
                # Build the URL based on where the parameters were found
                if is_fragment_based:
                    # For SPAs with parameters in fragment
                    frag_base = parsed.fragment.split('?')[0]
                    param_str = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    fuzzed_url = f"{base}#{frag_base}?{param_str}"
                else:
                    # For regular URLs with query parameters
                    param_str = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    fuzzed_url = f"{base}?{param_str}"
                
                urls.append((fuzzed_url, param, payload, category))
        
        print(f"Generated {len(urls)} URLs for fuzzing with {len(params)} parameters and {len(payloads)} payloads")
        return urls

    async def analyze_response(self, response, param, payload, category):
        """Analyze the response for signs of vulnerabilities"""
        if not response["success"]:
            return
            
        score = 0
        evidence = []
        content = response.get("content", "").lower()
        
        # General reflection
        if str(payload).lower() in content:
            score += 3
            evidence.append("Reflected input detected")
        
        # Error-based detection
        error_keywords = ["error", "warning", "exception", "syntax", "unexpected", "invalid", "failed", "failure"]
        if any(keyword in content for keyword in error_keywords):
            score += 2
            evidence.append("Error messages detected")
        
        # SQL injection specific
        sql_errors = ["sql", "mysql", "syntax error", "ora-", "postgresql", "sqlite", "database error"]
        if category == "sql" and any(err in content for err in sql_errors):
            score += 3
            evidence.append("SQL error detected")
        
        # XSS detection - look for script execution signs
        if category == "xss" and (
            "<script" in content or 
            "onerror" in content or 
            "javascript:" in content
        ):
            score += 3
            evidence.append("Possible XSS vulnerability")
        
        # Path traversal - look for file content
        if category == "path" and (
            "root:" in content or 
            "localhost" in content or
            "/bin/" in content or
            "windows\\system32" in content
        ):
            score += 4
            evidence.append("File content exposed")
        
        # Status code-based detection
        if response.get("status", 0) == 500:
            score += 3
            evidence.append("Server error (500)")
        elif response.get("status", 0) == 403:
            score += 2
            evidence.append("Access forbidden (403)")
        elif response.get("status", 0) == 401:
            score += 2
            evidence.append("Authentication required (401)")
        
        # Add to results
        self.results.append({
            "url": response.get("url", ""),
            "param": param,
            "payload": payload,
            "category": category,
            "evidence": evidence,
            "response_time": response.get("response_time", 0),
            "status": response.get("status", 0),
            "content_type": response.get("headers", {}).get("Content-Type", ""),
            "score": score,
            "size": len(response.get("content", ""))
        })

    def set_progress_callback(self, callback):
        """Set a callback function to report progress during fuzzing.
        The callback should accept three parameters:
        - completed: number or percentage of parameters processed
        - total: total number of parameters to process
        - message: current status message
        """
        self.progress_callback = callback

    async def fuzz_param(self, url_info):
        """Test a single parameter with a specific payload"""
        url, param, payload, category = url_info
        async with self.semaphore:
            response = await self.request_handler.send_request(url)
            await self.analyze_response(response, param, payload, category)
            
            # Update progress
            self.completed_tests += 1
            if self.progress_callback:
                progress_percentage = int((self.completed_tests / self.total_tests) * 100)
                self.progress_callback(
                    progress_percentage,
                    self.total_tests,
                    f"Testing parameters: {self.completed_tests}/{self.total_tests} complete ({progress_percentage}%)"
                )
                
            await asyncio.sleep(self.request_delay)

    async def run(self):
        """Run the parameter fuzzing process."""
        start_time = time.time()
        
        # Load payloads if not already loaded
        if not self.payloads:
            self.load_payloads()
            
        # Generate URLs for fuzzing
        urls_to_test = self.generate_urls(self.payloads)
        self.total_tests = len(urls_to_test)
        self.completed_tests = 0
        
        # Report initial progress
        if self.progress_callback:
            self.progress_callback(0, self.total_tests, f"Starting parameter fuzzing with {self.total_tests} tests on {self.target_url}")
        
        print(f"Running {len(urls_to_test)} parameter tests...")

        # Process URLs in chunks to control concurrency
        chunk_size = self.async_requests
        for i in range(0, len(urls_to_test), chunk_size):
            chunk = urls_to_test[i:i + chunk_size]
            
            # Create tasks for each URL in the chunk
            tasks = []
            for url_data in chunk:
                task = asyncio.create_task(self.fuzz_param(url_data))
                tasks.append(task)
                
            # Wait for all tasks in the chunk to complete
            await asyncio.gather(*tasks)
            
            # Add delay between chunks
            if self.request_delay > 0:
                await asyncio.sleep(self.request_delay)
        
        # Sort results by score (descending)
        self.results.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        processing_time = time.time() - start_time
        print(f"Completed parameter fuzzing with {len(self.results)} results")
        
        # Report completion
        if self.progress_callback:
            vulnerable_count = sum(1 for r in self.results if r.get('score', 0) > 3)
            self.progress_callback(
                100,
                self.total_tests,
                f"Parameter fuzzing completed. Found {vulnerable_count} potentially vulnerable parameters."
            )
            
        return self.results

    def save_results(self, filepath="parameter_fuzz_results.json"):
        """Save results to a JSON file"""
        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"Results saved to {filepath}")

if __name__ == "__main__":
    import sys
    import os
    
    # Add the project root to PYTHONPATH
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, project_root)
    
    async def main():
        url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com/search?q=FUZZ"
        fuzzer = ParameterFuzzer(url)
        await fuzzer.run()
        fuzzer.save_results()
        print(f"\n[+] Fuzzing complete. Found {len(fuzzer.results)} results.")
        print(f"[+] Results saved to parameter_fuzz_results.json")

    asyncio.run(main())
