# src/fuzzing/parameter_fuzzer.py
import asyncio
import json
import os
import re
from urllib.parse import urlparse, urlencode

from src.utils.request_handler import AsyncRequestHandler

class ParameterFuzzer:
    def __init__(self, base_url, payload_dir="src/payloads", delay=0.2, max_concurrency=5):
        self.base_url = base_url
        self.payload_dir = payload_dir
        self.delay = delay
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.request_handler = AsyncRequestHandler()
        self.results = []

    def load_payloads(self):
        payloads = []
        for file in os.listdir(self.payload_dir):
            path = os.path.join(self.payload_dir, file)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append((file.replace(".txt", ""), line))
        return payloads

    def generate_urls(self, payloads):
        parsed = urlparse(self.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query_params = dict([part.split("=") for part in parsed.query.split("&") if "=" in part])

        urls = []
        for param in query_params:
            for category, payload in payloads:
                test_params = query_params.copy()
                test_params[param] = payload
                fuzzed_url = f"{base}?{urlencode(test_params)}"
                urls.append((fuzzed_url, param, payload, category))
        return urls

    async def analyze_response(self, response, param, payload, category):
        score = 0
        evidence = []

        if payload in response["content"]:
            score += 3
            evidence.append("Reflected input detected")
        if any(keyword in response["content"].lower() for keyword in ["error", "warning", "unexpected", "sql", "exception"]):
            score += 2
            evidence.append("Suspicious keywords found")
        if response["status"] in [500, 403, 400]:
            score += 1
            evidence.append(f"Status code: {response['status']}")

        if score >= 3:
            self.results.append({
                "url": response["url"],
                "param": param,
                "payload": payload,
                "category": category,
                "evidence": evidence,
                "response_time": response["response_time"],
                "status": response["status"]
            })

    async def fuzz_param(self, url_info):
        url, param, payload, category = url_info
        async with self.semaphore:
            response = await self.request_handler.send_request(url)
            if response["success"]:
                await self.analyze_response(response, param, payload, category)
            await asyncio.sleep(self.delay)

    async def run(self):
        payloads = self.load_payloads()
        urls = self.generate_urls(payloads)
        await asyncio.gather(*[self.fuzz_param(url_info) for url_info in urls])

    def save_results(self, filepath="parameter_fuzz_results.json"):
        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2)

if __name__ == "__main__":
    import sys
    async def main():
        url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com/search?q=FUZZ"
        fuzzer = ParameterFuzzer(url)
        await fuzzer.run()
        fuzzer.save_results()
        print(f"\n[+] Fuzzing complete. Results saved to parameter_fuzz_results.json")

    asyncio.run(main())
