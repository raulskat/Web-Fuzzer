# src/fuzzing/subdomains.py
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utils.logger import setup_logger
from src.utils.config_loader import load_config

# Load the configuration
config = load_config()

# Accessing config settings
if config['subdomains']['enabled']:
    # Run the directory fuzzing logic
    print("SubDomain fuzzing enabled!")

class SubdomainFuzzer:
    def __init__(self, domain, wordlist, threads=5, delay=0.5):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.delay = delay
        self.logger = setup_logger("subdomain_fuzzer",config["logging"]["log_file"])
        self.discovered_subdomains = []
    
    def process_response(self, fqdn, response):
        """Process the DNS response and log results."""
        if response is None:
            self.logger.warning(f"No response for subdomain: {fqdn}")
            return
        if response.status_code == 200:
            self.logger.info(f"Valid subdomain found: {fqdn}: {response.status_code}")
        elif response.status_code == 403:
            self.logger.info(f"Access forbidden to subdomain: {fqdn}: {response.status_code}")
        elif response.status_code == 500:
            self.logger.info(f"Server error for subdomain: {fqdn}: {response.status_code}")
        else:
            self.logger.info(f"Unexpected response for subdomain {fqdn}: {response.status_code}")

    def test_subdomain(self, subdomain):
        """Resolve a subdomain and process the response."""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            # Resolve the subdomain DNS records
            dns.resolver.resolve(fqdn, 'A')  # 'A' record for IPv4 addresses
            response = True  # Simulating a successful DNS resolution response
            self.process_response(fqdn, response)  # Process the DNS response
            self.discovered_subdomains.append(fqdn)
        except dns.resolver.NoAnswer:
            self.logger.warning(f"No DNS record found for subdomain: {fqdn}")
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"Subdomain does not exist: {fqdn}")
        except Exception as e:
            self.logger.error(f"Error while resolving {fqdn}: {str(e)}")


    def resolve_subdomain(self, subdomain):
        """
        Attempt to resolve a subdomain.

        Args:
            subdomain (str): The subdomain to resolve.

        Returns:
            tuple: A tuple (subdomain, status) where `status` is either
                   "discovered", "no_record", "nonexistent", or "error".
        """
        fqdn = f"{subdomain}.{self.domain}"
        try:
            dns.resolver.resolve(fqdn, 'A')  # Attempt DNS resolution
            self.logger.info(f"Discovered subdomain: {fqdn}")
            return fqdn, "discovered"
        except dns.resolver.NoAnswer:
            self.logger.warning(f"No DNS record found for: {fqdn}")
            return fqdn, "no_record"
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"Domain does not exist: {fqdn}")
            return fqdn, "nonexistent"
        except Exception as e:
            self.logger.error(f"Error while resolving {fqdn}: {str(e)}")
            return fqdn, "error"

    def fuzz_subdomains(self):
        """
        Perform subdomain discovery using the provided wordlist.
        
        Returns:
            list: A list of successfully discovered subdomains.
        """
        if config['subdomains']['enabled']:
            self.logger.info(f"Starting subdomain fuzzing on domain: {self.domain}")
            discovered_subdomains = []

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {
                    executor.submit(self.resolve_subdomain, subdomain): subdomain for subdomain in self.wordlist
                }
                for future in as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        fqdn, status = future.result()
                        if status == "discovered":
                            discovered_subdomains.append(fqdn)
                    except Exception as e:
                        self.logger.error(f"Error while processing subdomain '{subdomain}': {str(e)}")

            self.logger.info(f"Fuzzing completed. Total discovered subdomains: {len(discovered_subdomains)}")
            return discovered_subdomains
        else:
            print("disabled subdomains in config")


# Example usage
if __name__ == "__main__":
    domain = config["target_domain"]
    wordlist_path = config["subdomains"]["wordlist"]
    if config["subdomains"]["enabled"] :
        # Load the wordlist from file
        with open(wordlist_path, "r") as file:
            wordlist = [line.strip() for line in file]

        fuzzer = SubdomainFuzzer(domain, wordlist,threads=5)
        discovered = fuzzer.fuzz_subdomains()
        print(f"Discovered Subdomains: {discovered}")
    else:
        print("disabled subdomains in config")
