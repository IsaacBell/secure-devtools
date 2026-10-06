import axios from "axios";
import got from "got";

import { assertPublicUrl, safeFetch } from "./net";

async function fetchFollowingRedirects(url: string) {
  // ruleid: ssrf-auto-redirect-javascript
  return axios(url, { maxRedirects: 5 });
}

async function fetchFollowingRedirectsGot(url: string) {
  // ruleid: ssrf-auto-redirect-javascript-got
  return got(url, { followRedirect: true });
}

async function fetchFixedUrlFollowingRedirects() {
  // ok: ssrf-auto-redirect-javascript
  return axios("https://api.example.com/v1/status", { maxRedirects: 5 });
}

async function fetchGuardedFollowingRedirects(url: string) {
  // ok: ssrf-auto-redirect-javascript
  return axios(assertPublicUrl(url), { maxRedirects: 5 });
}

async function fetchNoAutoRedirect(url: string) {
  // ok: ssrf-auto-redirect-javascript
  return axios(url, { maxRedirects: 0 });
}

async function fetchViaHelper(url: string) {
  // ok: ssrf-auto-redirect-javascript
  return safeFetch(url);
}
