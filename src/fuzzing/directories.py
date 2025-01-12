# src/fuzzing/directories.py
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utils.logger import setup_logger
from src.utils.request_handler import RequestHandler
from src.utils.config_loader import load_config

# Load the configuration
config = load_config()

# Accessing config settings
if config['directories']['enabled']:
    # Run the directory fuzzing logic
    print("Directory fuzzing enabled!")

class DirectoryFuzzer:
    def __init__(self, base_url, wordlist, threads=5, delay=0.5,log_file="directory_fuzzer.log"):
        self.base_url = base_url
        self.wordlist = wordlist  # Accept wordlist directly as an argument
        self.request_handler = RequestHandler()
        self.threads = threads
        self.delay = delay
        self.logger = setup_logger("directory_fuzzer",config["logging"]["log_file"])
        self.logger = setup_logger("directory_fuzzer",log_file)
    
    def load_wordlist(self):
        """Return the wordlist directly (since you're passing it directly)."""
        return self.wordlist  # Just return the wordlist passed in the constructor

    def process_response(self, url, response):
        # """Process the HTTP response and log results."""
        if response is None:
            self.logger.warning(f"No response for path: {url}")
            return
        if response.status_code == 404:
            self.logger.info(f"Path not found: {url}")
            return url, "not_found"
        elif response.status_code == 200:
            self.logger.info(f"Valid path found: {url}")
            return url, "valid"
        elif response.status_code == 403:
            self.logger.info(f"Access forbidden: {url}")
            return url, "forbidden"
        elif response.status_code == 500:
            self.logger.info(f"Server error on path: {url}")
            return url, "Server_error"
        else:
            self.logger.info(f"Unexpected status code {response.status_code} for path: {url}")
            return url, "unexpected"
    
    def test_directory(self, path):
        """Send a request to a single directory and process the response."""
        url = f"{self.base_url}/{path}"
        try:
            response = self.request_handler.send_request(url)
            return self.process_response(url, response)
        except Exception as e:
            self.logger.error(f"Error occurred while testing {path}: {str(e)}")
            return None

    def fuzz_directories(self):
    # """Perform directory fuzzing with parallel processing."""
        if config['directories']['enabled']:
            wordlist = self.load_wordlist()
            if not wordlist:
                self.logger.error("Wordlist is empty or could not be loaded.")
                return []

            self.logger.info(f"Starting directory fuzzing on {self.base_url}")
            results = []

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_path = {executor.submit(self.test_directory, path): path for path in wordlist}
                for future in as_completed(future_to_path):
                    path = future_to_path[future]
                    try:
                        result = future.result()  # test_directory handles processing
                        if result and result[1]== "valid":
                            results.append(result[0])
                    except Exception as e:
                        self.logger.error(f"Error while processing path '{path}': {str(e)}")
                    time.sleep(self.delay)

            self.logger.info(f"Fuzzing completed. Total paths tested: {len(wordlist)}.")
            return results
        else:
            print("disabled directories in config")

            

# Example usage
if __name__ == "__main__":
    base_url = config["target_url"]
    wordlist_path = config["directories"]["wordlist"]
    # Load the wordlist from file
    with open(wordlist_path, "r") as file:
        wordlist = [line.strip() for line in file]

    fuzzer = DirectoryFuzzer(base_url, wordlist)
    discovered=fuzzer.fuzz_directories()
    print(f"Discovered directories: {discovered}")
    
