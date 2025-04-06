import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utils.logger import setup_logger
from src.utils.request_handler import RequestHandler
from src.utils.config_loader import load_config

# Load the configuration
config = load_config()

# Accessing config settings
if config['api_endpoints']['enabled']:
    # Run the directory fuzzing logic
    print("API Endpoints fuzzing enabled!")

class ApiFuzzer:
    def __init__(self, base_url, endpoints, methods=["GET", "POST", "PUT", "DELETE"], threads=5, delay=0.5):
        self.base_url = base_url
        self.endpoints = endpoints
        self.methods = methods
        self.request_handler = RequestHandler()
        self.threads = threads
        self.delay = delay
        self.logger = setup_logger("api_fuzzer",config["logging"]["log_file"])

    def load_endpoints(self):
        """Return the endpoints directly (since you're passing it directly)."""
        return self.endpoints  # Just return the endpoints passed in the constructor
    
    def process_response(self, url, method, response):
        """Process the HTTP response and log results."""
        if response is None:
            self.logger.warning(f"No response for {method} on {url}")
            return
        if response['status'] == 404:
            self.logger.info(f"Path not found for {method} on {url}")
            return url, method, "not_found"
        elif 300 <= response['status'] < 400:
            self.logger.info(f"Redirection detected: {url}")
            return url, "redirect"

        elif response['status'] == 200:
            self.logger.info(f"Valid path found for {method} on {url}")
            return url, method, "valid"
        elif response['status'] == 403:
            self.logger.info(f"Access forbidden for {method} on {url}")
            return url, method, "forbidden"
        elif response['status'] == 500:
            self.logger.info(f"Server error for {method} on {url}")
            return url, method, "server_error"
        else:
            self.logger.info(f"Unexpected status code {response['status']} for {method} on {url}")
            return url, method, "unexpected"

    def test_endpoint(self, url, method):
        """Send a request to a single API endpoint and process the response."""
        try:
            response = self.request_handler.send_request(url, method)
            return self.process_response(url, method, response)
        except Exception as e:
            self.logger.error(f"Error occurred while testing {method} on {url}: {str(e)}")
            return None

    def fuzz_api_endpoints(self):
        """Perform API fuzzing with parallel processing."""
        if config['api_endpoints']['enabled']:
            endpoints = self.load_endpoints()
            if not endpoints:
                self.logger.error("Endpoints list is empty or could not be loaded.")
                return []

            self.logger.info(f"Starting API fuzzing on {self.base_url}")
            results = []

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_endpoint = {}

                # Submit tasks for each endpoint and HTTP method combination
                for endpoint in endpoints:
                    url = f"{self.base_url}{endpoint}"
                    for method in self.methods:
                        future = executor.submit(self.test_endpoint, url, method)
                        future_to_endpoint[future] = (url, method)

                # Process completed futures
                for future in as_completed(future_to_endpoint):
                    url, method = future_to_endpoint[future]
                    result = future.result()
                    if result:
                        results.append(result)

                    # Adding delay to avoid overwhelming the target server
                    time.sleep(self.delay)

            self.logger.info(f"Fuzzing completed. Total endpoints tested: {len(endpoints) * len(self.methods)}.")
            return results
        else:
            print("disabled api_endpoints in config")


# Example usage
if __name__ == "__main__":
    base_url = config["target_url"]
    endpoints_path = config['api_endpoints']['wordlist']
    if config['api_endpoints']['enabled']:
        # Load the endpoints from file
        with open(endpoints_path, "r") as file:
            endpoints = [line.strip() for line in file]

        fuzzer = ApiFuzzer(base_url, endpoints)
        print(f"{base_url}")
        discovered = fuzzer.fuzz_api_endpoints()
        print(f"Discovered API responses:{discovered}")
        for url, method, status in discovered:
            print(f"{url} [{method}]: {status}")
    else:
        print("disabled api_endpoints in config")
