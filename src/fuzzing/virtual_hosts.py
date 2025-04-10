import requests
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional


class VirtualHostFuzzer:
    """
    A class for fuzzing virtual hosts on a target IP address
    """
    
    def __init__(
        self, 
        target_ip: str, 
        wordlist: List[str], 
        threads: int = 10, 
        timeout: int = 10
    ):
        """
        Initialize the VirtualHostFuzzer

        Args:
            target_ip: The IP address of the target server
            wordlist: List of domain names to test as virtual hosts
            threads: Number of threads to use for concurrent requests
            timeout: Timeout in seconds for each request
        """
        self.target_ip = target_ip
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.results = []
        self.session = requests.Session()
        self.queue = queue.Queue()
        
        # Validate IP address format
        if not self._validate_ip(target_ip):
            raise ValueError("Invalid IP address format")
            
    def _validate_ip(self, ip: str) -> bool:
        """
        Validate the IP address format
        
        Args:
            ip: The IP address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not part.isdigit():
                    return False
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False
            
    def _make_request(self, domain: str) -> Dict[str, Any]:
    
        url = f"http://{self.target_ip}"
        headers = {"Host": domain}
        
        try:
            start_time = time.time()
            # Allow redirects to follow 301 responses automatically
            response = self.session.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                allow_redirects=True  # Allow automatic redirects
            )
            elapsed_time = time.time() - start_time
            
            # If there was a redirection, record the final URL
            final_url = response.url
            is_redirected = (response.status_code in [301, 302]) and (final_url != url)
            
            return {
                "domain": domain,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "response_time": elapsed_time,
                "headers": dict(response.headers),
                "title": self._extract_title(response.text),
                "redirect_url": response.headers.get("Location", ""),
                "final_url": final_url if is_redirected else "",  # Track the final URL after redirect
                "is_redirected": is_redirected  # Flag to check if the domain was redirected
            }
        except requests.RequestException as e:
            return {
                "domain": domain,
                "status_code": 0,
                "content_length": 0,
                "response_time": 0,
                "headers": {},
                "title": "",
                "redirect_url": "",
                "final_url": "",
                "is_redirected": False,
                "error": str(e)
            }
          
    def _extract_title(self, html: str) -> str:
        """
        Extract the title from HTML content
        
        Args:
            html: The HTML content
            
        Returns:
            str: The extracted title or empty string
        """
        try:
            start_index = html.lower().find("<title>")
            if start_index == -1:
                return ""
            
            start_index += 7  # Length of "<title>"
            end_index = html.lower().find("</title>", start_index)
            
            if end_index == -1:
                return ""
                
            return html[start_index:end_index].strip()
        except:
            return ""
            
    def _worker(self) -> None:
        """
        Worker function for threaded requests
        """
        while not self.queue.empty():
            try:
                domain = self.queue.get_nowait()
                result = self._make_request(domain)
                self.results.append(result)
            except queue.Empty:
                break
            finally:
                if not self.queue.empty():
                    self.queue.task_done()
                    
    def fuzz(self) -> List[Dict[str, Any]]:
        """
        Start the virtual host fuzzing process
        
        Returns:
            List of dictionaries containing the results
        """
        # Reset results
        self.results = []
        
        # Fill the queue with domains from wordlist
        for domain in self.wordlist:
            self.queue.put(domain)
            
        # Create and start worker threads
        threads = []
        for _ in range(min(self.threads, len(self.wordlist))):
            thread = threading.Thread(target=self._worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
            
        # Filter and sort results (typically showing valid hosts first)
        sorted_results = sorted(
            self.results, 
            key=lambda x: (x["status_code"] == 0, x["status_code"] != 200, x["content_length"]),
        )
        
        return sorted_results
        
    def fuzz_with_progress(self, callback=None) -> List[Dict[str, Any]]:
        """
        Start fuzzing with progress reporting
        
        Args:
            callback: Optional callback function to report progress
            
        Returns:
            List of dictionaries containing the results
        """
        # Reset results
        self.results = []
        total = len(self.wordlist)
        completed = 0
        
        # Use ThreadPoolExecutor for easier progress tracking
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._make_request, domain): domain for domain in self.wordlist}
            
            for future in futures:
                result = future.result()
                self.results.append(result)
                completed += 1
                
                if callback:
                    progress = (completed / total) * 100
                    callback(progress, result)
                    
        # Sort results
        sorted_results = sorted(
            self.results, 
            key=lambda x: (x["status_code"] == 0, x["status_code"] != 200, x["content_length"]),
        )
        
        return sorted_results

import sys

def main():
    if len(sys.argv) < 3:
        print("Usage: python virtual_host_fuzzer.py <target_ip> <wordlist_file>")
        sys.exit(1)

    target_ip = sys.argv[1]
    wordlist_file = sys.argv[2]
    
    # Load wordlist from the file
    try:
        with open(wordlist_file, "r") as f:
            wordlist = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"Error: The file '{wordlist_file}' was not found.")
        sys.exit(1)
    
    # Create an instance of the VirtualHostFuzzer class
    fuzzer = VirtualHostFuzzer(target_ip, wordlist)
    
    print(f"Starting fuzzing on {target_ip} with {len(wordlist)} domains...")
    
    # Run fuzzing and get results
    results = fuzzer.fuzz()
    
    print("\nFuzzing complete. Results:")
    for result in results:
        print(f"Domain: {result['domain']}, Status: {result['status_code']}, "
              f"Content Length: {result['content_length']}, Response Time: {result['response_time']:.2f} seconds")
        
    # Optionally, save the results to a file
    with open("fuzzing_results.json", "w") as f:
        import json
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    main()
