# src/utils/request_handler.py
import aiohttp
import asyncio
import requests
from requests.exceptions import RequestException
import time
import datetime

class RequestHandler:
    def __init__(self, timeout=10, max_retries=3, verify_ssl=True):
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

    def send_request(self, url, method="GET", headers=None):
        """
        Synchronous version of send_request using the requests library.
        Returns a dictionary with response information.
        """
        attempts = 0
        headers = headers or self.default_headers
        
        while attempts < self.max_retries:
            try:
                start_time = time.time()
                response = requests.request(method, url, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
                response_time = time.time() - start_time
                
                content = response.content
                content_length = len(content)
                
                try:
                    content_str = content.decode('utf-8')
                except UnicodeDecodeError:
                    content_str = f"[Binary content of {content_length} bytes]"
                
                return {
                    "url": url,
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "content": content_str,
                    "size": content_length,
                    "content_type": response.headers.get('Content-Type', ''),
                    "response_time": int(response_time * 1000),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "success": True,
                    "error": None
                }
                
            except requests.Timeout:
                attempts += 1
                if attempts >= self.max_retries:
                    return {
                        "url": url,
                        "status": 408,
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": int(self.timeout * 1000),
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": "Timeout"
                    }
            except requests.ConnectionError:
                attempts += 1
                if attempts >= self.max_retries:
                    return {
                        "url": url,
                        "status": 503,
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": 0,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": "Connection Error"
                    }
            except RequestException as e:
                attempts += 1
                if attempts >= self.max_retries:
                    print(f"[ERROR] Request to {url} failed after {self.max_retries} retries: {e}")
                    return {
                        "url": url,
                        "status": 404,
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": 0,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": str(e)
                    }
    
    async def send_request_async(self, url, method="GET", headers=None):
        attempts = 0
        headers = headers or self.default_headers

        while attempts < self.max_retries:
            try:
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                async with aiohttp.ClientSession(headers=headers, connector=connector) as session:

                    start_time = time.time()
                    async with session.request(method, url, timeout=self.timeout) as response:
                        response_time = time.time() - start_time
                        content = await response.read()
                        content_length = len(content)

                        try:
                            content_str = content.decode('utf-8')
                        except UnicodeDecodeError:
                            content_str = f"[Binary content of {content_length} bytes]"

                        serializable_headers = {k: str(v) for k, v in response.headers.items()}

                        return {
                            "url": url,
                            "status": response.status,
                            "headers": serializable_headers,
                            "content": content_str,
                            "size": content_length,
                            "content_type": response.headers.get('Content-Type', ''),
                            "response_time": int(response_time * 1000),
                            "timestamp": datetime.datetime.now().isoformat(),
                            "success": True,
                            "error": None
                        }
            except asyncio.TimeoutError:
                attempts += 1
                if attempts >= self.max_retries:
                    return {
                        "url": url,
                        "status": 408,
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": int(self.timeout * 1000),
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": "Timeout"
                    }
            except aiohttp.ClientConnectionError:
                attempts += 1
                if attempts >= self.max_retries:
                    return {
                        "url": url,
                        "status": 503,
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": 0,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": "Connection Error"
                    }
            except aiohttp.ClientError as e:
                attempts += 1
                if attempts >= self.max_retries:
                    print(f"[ERROR] Request to {url} failed after {self.max_retries} retries: {e}")
                    return {
                        "url": url,
                        "status": 404,
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": 0,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": str(e)
                    }
