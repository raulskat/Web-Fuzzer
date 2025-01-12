from src.fuzzing.directories import DirectoryFuzzer
from src.fuzzing.subdomains import SubdomainFuzzer
from src.fuzzing.api_endpoints import ApiFuzzer

# Sample configurations
directory_url="https://demo.owasp-juice.shop/#"
domain = "owasp-juice.shop"
base_url = f"http://{domain}"
directory_wordlist= ["admin","backup","test","config","check"]
subdomain_wordlist = ["www", "api", "dev", "staging", "blog"]
api_endpoints = ["/api/v1/users", "/admin", "/login", "/logout"]

# Discover directories using DirectoryFuzzer
directory_fuzzer=DirectoryFuzzer(directory_url,directory_wordlist)
discovered_directory=directory_fuzzer.fuzz_directories()
print(f"Discovered directories: {discovered_directory}")
# Discover subdomains using SubdomainFuzzer
subdomain_fuzzer = SubdomainFuzzer(domain, subdomain_wordlist, threads=5)
discovered_subdomains = subdomain_fuzzer.fuzz_subdomains()
print(f"Discovered Subdomains: {discovered_subdomains}")

# Fuzz API endpoints
api_responses = ApiFuzzer(directory_url, api_endpoints)
discovered_endpoints=api_responses.fuzz_api_endpoints()
print(f"API Responses: {discovered_endpoints}")
