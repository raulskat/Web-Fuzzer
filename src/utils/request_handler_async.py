# src/utils/request_handler_async.py
import aiohttp
import asyncio
import datetime
import time

class AsyncRequestHandler:
    def __init__(self, timeout=5, max_retries=3, ssl_verify=True):
        self.timeout = timeout
        self.max_retries = max_retries
        self.ssl_verify = ssl_verify

    async def send_request(self, session, url, method="GET", headers=None):
        attempts = 0

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
                    return {
                        "url": url,
                        "status": 400,
                        "headers": {},
                        "content": "",
                        "size": 0,
                        "content_type": "",
                        "response_time": 0,
                        "timestamp": datetime.datetime.now().isoformat(),
                        "success": False,
                        "error": str(e)
                    }
