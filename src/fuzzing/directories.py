
# src/fuzzing/directories.py
import time
# import asyncio - No longer needed for synchronous requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from src.utils.logger import setup_logger
from src.utils.request_handler import RequestHandler
from src.utils.config_loader import load_config
from src.utils.report_generator import ReportGenerator
import os
from dotenv import load_dotenv
import cohere

# Load environment variables from .env file
load_dotenv()

# Load the configuration
config = load_config()

# Accessing config settings
if config['directories']['enabled']:
    # Run the directory fuzzing logic
    print("Directory fuzzing enabled!")

class DirectoryFuzzer:
    def __init__(self, target_url, wordlist_source="both", custom_wordlist_path=None, threads=5, delay=0.5, verify_ssl=True):
        self.base_url = target_url
        self.wordlist_source = wordlist_source  # Can be "ai", "predefined", or "both"
        self.custom_wordlist_path = custom_wordlist_path
        self.verify_ssl = verify_ssl
        self.request_handler = RequestHandler(verify_ssl=verify_ssl)
        self.threads = threads
        self.delay = delay
        self.logger = setup_logger("directory_fuzzer", config["logging"]["log_file"])
        self.report_gen = ReportGenerator()  # Initialize a new ReportGenerator instance
        
        # Validate wordlist_source
        if wordlist_source not in ["ai", "predefined", "both"]:
            self.logger.warning(f"Invalid wordlist_source '{wordlist_source}'. Using 'both' as default.")
            self.wordlist_source = "both"
    
    def generate_wordlist_with_ai(self, prompt, max_tokens=100):
        """Generate a wordlist using Cohere's language model."""
        cohere_api_key = os.getenv('COHERE_API_KEY')
        if not cohere_api_key:
            self.logger.error("Cohere API key not found in environment variables.")
            return []
        co = cohere.Client(cohere_api_key)
        response = co.generate(
            model='command-r-plus',
            prompt=prompt,
            max_tokens=max_tokens,
            temperature=0.7,
            k=1,
            stop_sequences=["\n"]
        )
        wordlist = response.generations[0].text.strip().split(',')
        wordlist=[word.strip() for word in wordlist if word.strip()]
        print(wordlist)
        return wordlist

    def load_wordlist(self):
        """Load wordlist from custom path or default path"""
        if self.custom_wordlist_path and os.path.exists(self.custom_wordlist_path):
            try:
                with open(self.custom_wordlist_path, "r") as file:
                    wordlist = [line.strip() for line in file if line.strip()]
                self.logger.info(f"Loaded custom wordlist from {self.custom_wordlist_path}")
                return wordlist
            except Exception as e:
                self.logger.error(f"Error loading custom wordlist: {str(e)}")
        
        # Fallback to default wordlist
        default_wordlist_path = config["directories"]["wordlist"]
        try:
            with open(default_wordlist_path, "r") as file:
                wordlist = [line.strip() for line in file if line.strip()]
            self.logger.info(f"Loaded default wordlist from {default_wordlist_path}")
            return wordlist
        except Exception as e:
            self.logger.error(f"Error loading default wordlist: {str(e)}")
            return []

    def save_wordlist(self, wordlist, filename="ai_generated_wordlist.txt"):
        """Save the AI-generated wordlist to a file."""
        with open(filename, "w") as file:
            file.write("\n".join(wordlist))
        self.logger.info(f"AI-generated wordlist saved to {filename}")
    def get_wordlist_based_on_source(self):
        """Get the wordlist based on the selected source."""
        if self.wordlist_source == "predefined":
            self.logger.info("Using only predefined wordlist for directory fuzzing")
            return self.load_wordlist()
        
        elif self.wordlist_source == "ai":
            self.logger.info("Using only AI-generated wordlist for directory fuzzing")
            prompt = f"just give the list of common directories for a website like {self.base_url} in the form of only those diresctories name and should only contain name (not even space or -)"
            try:
                ai_wordlist = self.generate_wordlist_with_ai(prompt)
                if ai_wordlist:
                    self.save_wordlist(ai_wordlist)
                    return ai_wordlist
                else:
                    self.logger.error("AI-generated wordlist is empty. Falling back to predefined wordlist.")
                    return self.load_wordlist()
            except Exception as e:
                self.logger.error(f"Error generating AI wordlist: {str(e)}. Falling back to predefined wordlist.")
                return self.load_wordlist()
        
        else:  # "both" or any other value as fallback
            self.logger.info("Using combined predefined and AI-generated wordlists for directory fuzzing")
            existing_wordlist = self.load_wordlist()
            try:
                prompt = f"just give the list of common directories for a website like {self.base_url} in the form of only those diresctories name and should only contain name (not even space or -)"
                ai_wordlist = self.generate_wordlist_with_ai(prompt)
                if ai_wordlist:
                    self.save_wordlist(ai_wordlist)
                    return list(set(existing_wordlist + ai_wordlist))
                else:
                    self.logger.error("AI-generated wordlist is empty. Using only predefined wordlist.")
                    return existing_wordlist
            except Exception as e:
                self.logger.error(f"Error generating AI wordlist: {str(e)}. Using only predefined wordlist.")
                return existing_wordlist

    # The process_response method is no longer needed as the processing is now done directly in test_directory
    # This method is kept commented out for reference
    """
    def process_response(self, url, response):
        # Process the HTTP response and log results.
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
        elif response.status_code == 301 or response.status_code == 302:
            redirect_url = response.headers.get('Location', 'unknown')
            self.logger.info(f"Redirect found: {url} -> {redirect_url}")
            return url, "redirect"
        elif response.status_code == 500:
            self.logger.info(f"Server error on path: {url}")
            return url, "server_error"
        else:
            self.logger.info(f"Unexpected status code {response.status_code} for path: {url}")
            return url, "unexpected"
    """
    
    def test_directory(self, path):
        """Send a request to a single directory and process the response."""
        url = f"{self.base_url}/{path}"
        try:
            # Use the RequestHandler to send a request and get the response dictionary
            # Using the synchronous version of send_request
            response_dict = self.request_handler.send_request(url)
            
            if response_dict is None:
                self.logger.warning(f"No response for path: {url}")
                return None
            
            # Get the current timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Check if we have a response dictionary with status info
            if isinstance(response_dict, dict) and 'url' in response_dict:
                # Create a standardized response with only the required fields
                status_code = response_dict.get('status')
                size = response_dict.get('size', 0)
                response_time = response_dict.get('response_time', 0)
                content_type = response_dict.get('content_type', 'text/html')
                
                # Ensure values are the right type
                if isinstance(size, str):
                    try:
                        size = int(size)
                    except ValueError:
                        size = 0
                
                if isinstance(response_time, str):
                    try:
                        response_time = int(response_time)
                    except ValueError:
                        response_time = 0
                
                # Create a clean response dictionary with only the required fields
                clean_response = {
                    "url": url,
                    "status": status_code,
                    "size": size,
                    "response_time": response_time,
                    "content_type": content_type,
                    "timestamp": timestamp
                }
                
                # Log the result
                self.logger.info(f"TESTED - {url} (Status: {status_code}, Size: {size}, Time: {response_time}ms)")
                return clean_response
            else:
                # Format the response in the desired dictionary structure if it's not already
                self.logger.warning(f"Unexpected response format for path: {url}")
                return {
                    "url": url,
                    "status": 0,
                    "size": 0,
                    "response_time": 0,
                    "content_type": "text/plain",
                    "timestamp": timestamp
                }
            
        except Exception as e:
            self.logger.error(f"Error occurred while testing {path}: {str(e)}")
            return None

    def fuzz_directories(self):
        if not config['directories']['enabled']:
            print("disabled directories in config")
            return []

        final_wordlist = []

        # Get wordlist based on source selection
        if self.wordlist_source in ["predefined", "both"]:
            predefined_wordlist = self.load_wordlist()
            if predefined_wordlist:
                final_wordlist.extend(predefined_wordlist)
                self.logger.info(f"Added {len(predefined_wordlist)} words from predefined wordlist")

        if self.wordlist_source in ["ai", "both"]:
            prompt = f"just give the list of common directories for a website like {self.base_url} in the form of only those directories name and should only contain name (not even space or -)"
            ai_wordlist = self.generate_wordlist_with_ai(prompt)
            if ai_wordlist:
                self.save_wordlist(ai_wordlist)
                final_wordlist.extend(ai_wordlist)
                self.logger.info(f"Added {len(ai_wordlist)} words from AI-generated wordlist")

        if not final_wordlist:
            self.logger.error("No wordlist available for fuzzing")
            return []

        # Remove duplicates and empty strings
        final_wordlist = list(set(filter(None, final_wordlist)))
        self.logger.info(f"Final wordlist contains {len(final_wordlist)} unique entries")

        results = []
        status_counts = {
            "2xx": 0,  # Success responses
            "3xx": 0,  # Redirect responses
            "4xx": 0,  # Client error responses
            "5xx": 0,  # Server error responses
            "error": 0 # Connection/request errors
        }
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {executor.submit(self.test_directory, path): path for path in final_wordlist}
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        # Update status counts based on status code
                        status_code = result.get("status", 0)
                        
                        if isinstance(status_code, int):
                            if 200 <= status_code < 300:
                                status_counts["2xx"] += 1
                            elif 300 <= status_code < 400:
                                status_counts["3xx"] += 1
                            elif 400 <= status_code < 500:
                                status_counts["4xx"] += 1
                            elif 500 <= status_code < 600:
                                status_counts["5xx"] += 1
                        else:
                            status_counts["error"] += 1
                        
                        # Add to results and report - result already has the proper structure
                        results.append(result)
                        self.report_gen.add_result("directories", result)
                except Exception as e:
                    self.logger.error(f"Error while processing path '{path}': {str(e)}")
                time.sleep(self.delay)

        # Log status count summary
        status_summary = ", ".join([f"{label}: {count}" for label, count in status_counts.items() if count > 0])
        self.logger.info(f"Fuzzing completed. Total paths tested: {len(final_wordlist)}. Results: {status_summary}")
        
        # Add metadata to the report
        metadata = {
            "target_url": self.base_url,
            "wordlist_source": self.wordlist_source,
            "total_tested": len(final_wordlist),
            "total_found": len(results),
            "status_counts": status_counts,
            "timestamp": datetime.now().isoformat(),
            "threads": self.threads,
            "delay": self.delay
        }
        self.report_gen.add_metadata("directories", metadata)
        
        # Save the report with a timestamp-based filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        report_filename = f"directories_{timestamp}.json"
        
        try:
            self.report_gen.save_report(f"results/{report_filename}")
            print(f"Results saved to results/{report_filename}")
        except Exception as e:
            self.logger.error(f"Error saving report: {str(e)}")
            print(f"Error saving report: {str(e)}")
            
            # If saving fails due to serialization, try to create a simplified report
            try:
                # Ensure all results have the exact same structure with clean values
                simplified_results = []
                for result in results:
                    simplified_result = {
                        "url": str(result.get("url", "")),
                        "status": int(result.get("status", 0)) if result.get("status") is not None else 0,
                        "size": int(result.get("size", 0)) if result.get("size") is not None else 0,
                        "response_time": int(result.get("response_time", 0)) if result.get("response_time") is not None else 0,
                        "content_type": str(result.get("content_type", "text/plain")),
                        "timestamp": str(result.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    }
                    simplified_results.append(simplified_result)
                
                # Create a new ReportGenerator with simplified results
                simplified_report = ReportGenerator()
                for result in simplified_results:
                    simplified_report.add_result("directories", result)
                simplified_report.add_metadata("directories", metadata)
                
                # Save the simplified report
                simplified_filename = f"directories_{timestamp}_simplified.json"
                simplified_report.save_report(f"results/{simplified_filename}")
                print(f"Simplified results saved to results/{simplified_filename}")
            except Exception as e2:
                self.logger.error(f"Error saving simplified report: {str(e2)}")
        
        return results

# Example usage
if __name__ == "__main__":
    base_url = config["target_url"]
    wordlist_path = config["directories"]["wordlist"]
    
    fuzzer = DirectoryFuzzer(
        target_url=base_url,
        wordlist_source="both",
        custom_wordlist_path=wordlist_path
    )
    discovered = fuzzer.fuzz_directories()
    print(f"Discovered directories: {discovered}")
    print(f"Report saved to {fuzzer.report_gen.output_file}")
    
