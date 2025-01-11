# src/fuzzing/directories.py
import os
from src.utils.logger import setup_logger
from src.utils.request_handler import RequestHandler

class DirectoryFuzzer:
    def __init__(self, base_url, wordlist_path, logger=None):
        self.base_url = base_url.rstrip('/')  # Ensure no trailing slash
        self.wordlist_path = wordlist_path
        self.request_handler = RequestHandler()
        self.logger = logger or setup_logger("directory_fuzzer", "directory_fuzzer.log")

    def load_wordlist(self):
        """Load wordlist from file."""
        if not os.path.exists(self.wordlist_path):
            self.logger.error(f"Wordlist file not found: {self.wordlist_path}")
            return []
        with open(self.wordlist_path, "r") as file:
            return [line.strip() for line in file if line.strip()]

    def fuzz_directories(self):
        """Perform directory fuzzing."""
        wordlist = self.load_wordlist()
        if not wordlist:
            self.logger.error("Wordlist is empty or could not be loaded.")
            return

        self.logger.info(f"Starting directory fuzzing on {self.base_url}")
        for path in wordlist:
            url = f"{self.base_url}/{path}"
            
            try:
                response = self.request_handler.send_request(url)
                print(response)
                # process response
            except Exception as e:
                self.logger.error(f"Error occurred while testing {path}: {str(e)}")

            if response.status_code == 404:
                self.logger.info(f"Path not found: {url}")
            elif response.status_code == 200:
                self.logger.info(f"Valid path found: {url}")
            elif response.status_code == 403:
                self.logger.info(f"Access forbidden: {url}")
            elif response.status_code == 500:
                self.logger.info(f"Server error on path: {url}")
            else:
                self.logger.info(f"Unexpected status code {response.status_code} for path: {url}")

            

# Example usage
if __name__ == "__main__":
    base_url = "https://www.flipkart.com/"
    wordlist_path = "src/wordlist.txt"

    fuzzer = DirectoryFuzzer(base_url, wordlist_path)
    fuzzer.fuzz_directories()
