import httpx
import requests
import urllib.request

from myapp.net import assert_public_url, check_public_url, safe_fetch


def preview_link(url):
    # ruleid: ssrf-unchecked-url-python
    return requests.get(url, timeout=5)


def send_webhook(target_url, payload):
    # ruleid: ssrf-unchecked-url-python
    return requests.post(target_url, json=payload)


def fetch_via_httpx(url):
    # ruleid: ssrf-unchecked-url-python
    return httpx.get(url)


def fetch_via_urllib(url):
    # ruleid: ssrf-unchecked-url-python
    return urllib.request.urlopen(url)


def fetch_fixed_api():
    # ok: ssrf-unchecked-url-python
    return requests.get("https://api.example.com/v1/status")


def fetch_checked(url):
    # ok: ssrf-unchecked-url-python
    return requests.get(check_public_url(url))


def fetch_asserted(url):
    # ok: ssrf-unchecked-url-python
    return httpx.get(assert_public_url(url))


def fetch_guarded_helper(url):
    # ok: ssrf-unchecked-url-python
    return requests.get(safe_fetch(url))
