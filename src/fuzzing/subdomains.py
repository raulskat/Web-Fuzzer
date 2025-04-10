# src/fuzzing/subdomains.py
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from src.utils.logger import setup_logger
from src.utils.config_loader import load_config

# Load the configuration
config = load_config()

# Accessing config settings
if config['subdomains']['enabled']:
    # Run the directory fuzzing logic
    print("SubDomain fuzzing enabled!")

class SubdomainFuzzer:
    def __init__(self, domain, wordlist, threads=5, delay=0.5, verify_ssl=True):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.logger = setup_logger("subdomain_fuzzer",config["logging"]["log_file"])
        self.discovered_subdomains = []
    
    def process_response(self, fqdn, response):
        """Process the DNS response and log results."""
        if response is None:
            self.logger.warning(f"No response for subdomain: {fqdn}")
            return {"url": fqdn, "status": 503, "size": 0, "response_time": 0, "content_type": "N/A", "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        if isinstance(response, bool):
            # DNS resolution was successful
            self.logger.info(f"Valid subdomain found: {fqdn}")
            return {
                "url": fqdn,
                "status": 200,  # DNS resolution successful
                "size": 0,
                "response_time": 0,
                "content_type": "DNS Record",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        else:
            # Response has a status code
            self.logger.info(f"Response for subdomain {fqdn}: {response.status_code}")
            return {
                "url": fqdn,
                "status": response.status_code,
                "size": len(response.content) if hasattr(response, 'content') else 0,
                "response_time": 0,
                "content_type": response.headers.get('Content-Type', 'N/A') if hasattr(response, 'headers') else 'N/A',
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

    def test_subdomain(self, subdomain):
        """Resolve a subdomain and process the response."""
        fqdn = f"{subdomain}.{self.domain}"
        try:
            # Resolve the subdomain DNS records
            dns.resolver.resolve(fqdn, 'A')  # 'A' record for IPv4 addresses
            response = True  # Successful DNS resolution response
            result = self.process_response(fqdn, response)  # Get processed response
            self.discovered_subdomains.append(result)
            return result
        except dns.resolver.NoAnswer:
            self.logger.warning(f"No DNS record found for subdomain: {fqdn}")
            return self.process_response(fqdn, None)
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"Subdomain does not exist: {fqdn}")
            return self.process_response(fqdn, None)
        except Exception as e:
            self.logger.error(f"Error while resolving {fqdn}: {str(e)}")
            return self.process_response(fqdn, None)


    def resolve_subdomain(self, subdomain):
        """
        Attempt to resolve a subdomain and check its HTTP availability.

        Args:
            subdomain (str): The subdomain to resolve.

        Returns:
            dict: A dictionary containing the subdomain's status and response information.
        """
        fqdn = f"{subdomain}.{self.domain}"
        try:
            # First attempt DNS resolution
            dns.resolver.resolve(fqdn, 'A')
            
            # If DNS resolution succeeds, try HTTP request
            url = f"https://{fqdn}"
            start_time = datetime.now()
            try:
                import requests
                response = requests.get(url, timeout=5, allow_redirects=False, verify=self.verify_ssl)
                response_time = (datetime.now() - start_time).total_seconds() * 1000
                
                return {
                    "url": url,
                    "status": response.status_code,
                    "size": len(response.content),
                    "response_time": int(response_time),
                    "content_type": response.headers.get('Content-Type', 'N/A'),
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            except requests.RequestException:
                # HTTP request failed but DNS resolved
                self.logger.info(f"DNS resolved but HTTP failed for: {fqdn}")
                return {
                    "url": url,
                    "status": 200,  # DNS resolved but HTTP failed
                    "size": 0,
                    "response_time": 0,
                    "content_type": "DNS Only",
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
        except dns.resolver.NoAnswer:
            self.logger.warning(f"No DNS record found for: {fqdn}")
            return {
                "url": f"https://{fqdn}",
                "status": 404,
                "size": 0,
                "response_time": 0,
                "content_type": "N/A",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"Domain does not exist: {fqdn}")
            return {
                "url": f"https://{fqdn}",
                "status": 404,
                "size": 0,
                "response_time": 0,
                "content_type": "N/A",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            self.logger.error(f"Error while resolving {fqdn}: {str(e)}")
            return {
                "url": f"https://{fqdn}",
                "status": 500,
                "size": 0,
                "response_time": 0,
                "content_type": "N/A",
                "error": str(e),
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

    def fuzz_subdomains(self):
        """
        Perform subdomain discovery using the provided wordlist.
        
        Returns:
            list: A list of discovered subdomains with their status information.
        """
        if config['subdomains']['enabled']:
            self.logger.info(f"Starting subdomain fuzzing on domain: {self.domain}")
            results = []

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {
                    executor.submit(self.resolve_subdomain, subdomain): subdomain 
                    for subdomain in self.wordlist
                }
                for future in as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        self.logger.error(f"Error while processing subdomain '{subdomain}': {str(e)}")
                        # Add error result
                        results.append({
                            "url": f"https://{subdomain}.{self.domain}",
                            "status": 500,
                            "size": 0,
                            "response_time": 0,
                            "content_type": "N/A",
                            "error": str(e),
                            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })

            self.logger.info(f"Fuzzing completed. Total processed subdomains: {len(results)}")
            return results
        else:
            print("disabled subdomains in config")
            return []


# Example usage
if __name__ == "__main__":
    domain = config["target_domain"]
    wordlist_path = config["subdomains"]["wordlist"]
    if config["subdomains"]["enabled"] :
        # Load the wordlist from file
        with open(wordlist_path, "r") as file:
            wordlist = [line.strip() for line in file]

        fuzzer = SubdomainFuzzer(domain, wordlist, threads=5, verify_ssl=True)
        discovered = fuzzer.fuzz_subdomains()
        print(f"Discovered Subdomains: {discovered}")
    else:
        print("disabled subdomains in config")
