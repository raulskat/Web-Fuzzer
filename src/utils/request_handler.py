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

# AsyncRequestHandler class used by parameter fuzzer
class AsyncRequestHandler:
    def __init__(self, timeout=5, max_retries=3, ssl_verify=True):
        self.timeout = timeout
        self.max_retries = max_retries
        self.ssl_verify = ssl_verify
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

    async def send_request(self, url, method="GET", headers=None):
        """
        Send a request to the specified URL and return the response.
        Creates its own session for the request.
        """
        headers = headers or self.default_headers
        attempts = 0
        
        while attempts < self.max_retries:
            try:
                # Create a client session for this request
                connector = aiohttp.TCPConnector(ssl=self.ssl_verify)
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    start_time = time.time()
                    
                    try:
                        async with session.request(method, url, headers=headers) as response:
                            # Read response content
                            content = await response.text(errors='replace')
                            end_time = time.time()
                            
                            return {
                                "success": True,
                                "url": url,
                                "status": response.status,
                                "headers": dict(response.headers),
                                "content": content,
                                "size": len(content),
                                "response_time": int((end_time - start_time) * 1000)  # ms
                            }
                    except aiohttp.ClientError as e:
                        print(f"Request error for {url}: {str(e)}")
                        attempts += 1
                        # Return error response
                        return {
                            "success": False,
                            "url": url,
                            "error": f"Request error: {str(e)}",
                            "status": 0,
                            "headers": {},
                            "content": "",
                            "size": 0,
                            "response_time": 0
                        }
            
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                print(f"Session error for {url}: {str(e)}")
                attempts += 1
                await asyncio.sleep(0.5)  # brief delay before retry
            
            except Exception as e:
                print(f"Unexpected error for {url}: {str(e)}")
                # Return error response
                return {
                    "success": False,
                    "url": url,
                    "error": f"Unexpected error: {str(e)}",
                    "status": 0,
                    "headers": {},
                    "content": "",
                    "size": 0,
                    "response_time": 0
                }
        
        # If we've exhausted all retries
        return {
            "success": False,
            "url": url,
            "error": "Maximum retry attempts reached",
            "status": 0,
            "headers": {},
            "content": "",
            "size": 0,
            "response_time": 0
        }

    # Keep the session-based method for other uses
    async def send_request_with_session(self, session, url, method="GET", headers=None):
        """
        Send a request using an existing session.
        This is the original method signature that was in request_handler_async.py
        """
        attempts = 0
        headers = headers or {}

        while attempts < self.max_retries:
            try:
                start_time = time.time()
                async with session.request(method, url, headers=headers, timeout=self.timeout, ssl=self.ssl_verify) as response:
                    response_time = time.time() - start_time
                    content = await response.read()

                    content_length = len(content)
                    try:
                        content_str = content.decode('utf-8')
                    except UnicodeDecodeError:
                        content_str = f"[Binary content of {content_length} bytes]"

                    return {
                        "url": url,
                        "status": response.status,
                        "headers": dict(response.headers),
                        "content": content_str,
                        "size": content_length,
                        "content_type": response.headers.get('Content-Type', ''),
                        "response_time": int(response_time * 1000),
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": True,
                        "error": None
                    }
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                attempts += 1
                if attempts >= self.max_retries:
                    error_type = "Timeout" if isinstance(e, asyncio.TimeoutError) else str(e)
                    status = 408 if isinstance(e, asyncio.TimeoutError) else 400
                    return {
                        "url": url,
                        "status": status,
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": 0,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": error_type
                    }
