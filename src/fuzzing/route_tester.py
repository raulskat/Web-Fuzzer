import requests
from datetime import datetime
from urllib.parse import urlparse, urljoin

class RouteHashTester:
    def __init__(self, base_url, timeout=5):
        """Initialize the route tester.
        
        Args:
            base_url (str): Base URL of the target application
            timeout (int): Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Web Application Fuzzer",
            "Accept": "*/*"
        }

    def test_hash_route(self, route):
        """Test a hash-based route.
        
        Args:
            route (str): The route to test (e.g., 'api/v1')
        
        Returns:
            dict: Response information
        """
        # Ensure route format
        route = route.lstrip('/#')
        url = f"{self.base_url}/#{route}"
        
        try:
            start_time = datetime.now()
            response = requests.get(
                self.base_url,  # Request the base URL
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            elapsed_time = (datetime.now() - start_time).total_seconds() * 1000

            return {
                "url": url,  # Return full URL with hash
                "status": response.status_code,
                "size": len(response.content),
                "response_time": int(elapsed_time),
                "content_type": response.headers.get('Content-Type', 'N/A'),
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

        except requests.RequestException as e:
            return {
                "url": url,
                "status": "Error",
                "size": 0,
                "response_time": 0,
                "content_type": "N/A",
                "error": str(e),
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

    def test_hash_routes(self, routes):
        """Test multiple hash-based routes.
        
        Args:
            routes (list): List of routes to test
        
        Returns:
            list: List of response information dictionaries
        """
        results = []
        for route in routes:
            result = self.test_hash_route(route)
            results.append(result)
        return results

