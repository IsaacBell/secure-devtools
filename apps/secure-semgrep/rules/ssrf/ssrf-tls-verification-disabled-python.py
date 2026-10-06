import httpx
import requests


def fetch_insecure(url):
    # ruleid: ssrf-tls-verification-disabled-python
    return requests.get(url, verify=False)


def fetch_insecure_session(url):
    session = requests.Session()
    # ruleid: ssrf-tls-verification-disabled-python
    session.verify = False
    return session.get(url)


def fetch_insecure_httpx(url):
    # ruleid: ssrf-tls-verification-disabled-python
    client = httpx.Client(verify=False)
    return client.get(url)


def fetch_secure(url):
    # ok: ssrf-tls-verification-disabled-python
    return requests.get(url, verify=True)


def fetch_secure_custom_ca(url):
    # ok: ssrf-tls-verification-disabled-python
    return requests.get(url, verify="/etc/ssl/internal-ca.pem")
