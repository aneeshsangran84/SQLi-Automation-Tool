"""
requester.py - Handles all HTTP communication (FIXED)

WHAT CHANGED:
    Added support for 'extra_params' so we can include required 
    parameters like Submit=Submit alongside our injection payload.
"""

import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Response:
    """
    A simplified response object that stores what we care about.
    """

    def __init__(self, status_code, content_length, elapsed, text, headers):
        self.status_code = status_code
        self.content_length = content_length
        self.elapsed = elapsed
        self.text = text
        self.headers = headers

    def __repr__(self):
        return (
            f"<Response status={self.status_code} "
            f"size={self.content_length} "
            f"time={self.elapsed:.3f}s>"
        )


class Requester:
    """
    HTTP client for SQLi testing.
    """

    def __init__(self, cookies=None, proxy=None, timeout=10):
        self.session = requests.Session()
        self.timeout = timeout

        if cookies:
            for name, value in cookies.items():
                self.session.cookies.set(name, value)

        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy,
            }

    def get(self, url, headers=None, params=None):
        return self._send("GET", url, headers=headers, params=params)

    def post(self, url, headers=None, data=None):
        return self._send("POST", url, headers=headers, data=data)

    def _send(self, method, url, headers=None, params=None, data=None):
        start_time = time.time()

        try:
            resp = self.session.request(
                method=method,
                url=url,
                headers=headers or {},
                params=params,
                data=data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            elapsed = time.time() - start_time

            return Response(
                status_code=resp.status_code,
                content_length=len(resp.content),
                elapsed=elapsed,
                text=resp.text,
                headers=dict(resp.headers),
            )

        except requests.exceptions.Timeout:
            elapsed = time.time() - start_time
            return Response(
                status_code=0,
                content_length=0,
                elapsed=elapsed,
                text="",
                headers={},
            )

        except requests.exceptions.RequestException as e:
            elapsed = time.time() - start_time
            print(f"    [!] Request error: {e}")
            return Response(
                status_code=-1,
                content_length=0,
                elapsed=elapsed,
                text="",
                headers={},
            )