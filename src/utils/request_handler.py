# src/utils/request_handler.py
import requests
import time
import datetime
class RequestHandler:
    def __init__(self, timeout=5, max_retries=3):
        self.timeout = timeout
        self.max_retries = max_retries

    def send_request(self, url, method="GET", headers=None):
        attempts = 0
        while attempts < self.max_retries:
            try:
                start_time = time.time()
                response = requests.request(method, url, headers=headers, timeout=self.timeout)
                response_time = time.time() - start_time
                
                # Store original content length
                content_length = len(response.content)
                
                # Try to decode content safely
                try:
                    content_str = response.content.decode('utf-8')
                except UnicodeDecodeError:
                    # If content can't be decoded as text, use a placeholder
                    content_str = f"[Binary content of {content_length} bytes]"
                
                # Ensure headers are serializable
                serializable_headers = {}
                for key, value in response.headers.items():
                    serializable_headers[key] = str(value)
                
                return {
                    "url": url,
                    "status": response.status_code,
                    "headers": serializable_headers,
                    "content": content_str,
                    "size": content_length,
                    "content_type": response.headers.get('Content-Type', ''),
                    "response_time": int(response_time * 1000),  # Convert to integer milliseconds
                    "timestamp": datetime.datetime.now().isoformat(),
                    "success": True,
                    "error": None
                }
            except requests.Timeout:
                attempts += 1
                if attempts >= self.max_retries:
                    return {
                        "url": url,
                        "status": 408,  # Request Timeout
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": int(self.timeout * 1000),  # Convert to integer milliseconds
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": "Timeout"
                    }
            except requests.ConnectionError:
                attempts += 1
                if attempts >= self.max_retries:
                    return {
                        "url": url,
                        "status": 503,  # Service Unavailable
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": 0,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": "Connection Error"
                    }
            except requests.RequestException as e:
                attempts += 1
                if attempts >= self.max_retries:
                    print(f"[ERROR] Request to {url} failed after {self.max_retries} retries: {e}")
                    return {
                        "url": url,
                        "status": 404,  # Not Found
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": 0,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": str(e)
                    }
