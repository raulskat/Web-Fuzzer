# src/utils/request_handler.py
import requests

class RequestHandler:
    def __init__(self, timeout=5, max_retries=3):
        self.timeout = timeout
        self.max_retries = max_retries

    def send_request(self, url, method="GET", headers=None):
        attempts = 0
        while attempts < self.max_retries:
            try:
                response = requests.request(method, url, headers=headers, timeout=self.timeout)
                return response
            except requests.RequestException as e:
                attempts += 1
                if attempts >= self.max_retries:
                    print(f"[ERROR] Request to {url} failed after {self.max_retries} retries: {e}")
                    return None
