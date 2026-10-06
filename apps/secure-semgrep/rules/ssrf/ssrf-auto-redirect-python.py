import httpx
import requests

from myapp.net import assert_public_url, safe_fetch


def fetch_following_redirects(url):
    # ruleid: ssrf-auto-redirect-python
    return requests.get(url, allow_redirects=True)


def fetch_following_redirects_httpx(url):
    # ruleid: ssrf-auto-redirect-python
    return httpx.get(url, follow_redirects=True)


def fetch_fixed_url_following_redirects():
    # ok: ssrf-auto-redirect-python
    return requests.get("https://api.example.com/v1/status", allow_redirects=True)


def fetch_guarded_following_redirects(url):
    # ok: ssrf-auto-redirect-python
    return requests.get(assert_public_url(url), allow_redirects=True)


def fetch_no_auto_redirect(url):
    # ok: ssrf-auto-redirect-python
    return requests.get(url, allow_redirects=False)


def fetch_via_helper(url):
    # ok: ssrf-auto-redirect-python
    return safe_fetch(url)
