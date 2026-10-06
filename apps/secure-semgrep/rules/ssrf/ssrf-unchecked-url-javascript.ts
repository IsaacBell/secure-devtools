import axios from "axios";
import got from "got";
import http from "node:http";
import https from "node:https";

import { assertPublicUrl, checkPublicUrl, safeFetch } from "./net";

async function previewLink(url: string) {
  // ruleid: ssrf-unchecked-url-javascript
  return fetch(url);
}

async function sendWebhook(targetUrl: string, payload: unknown) {
  // ruleid: ssrf-unchecked-url-javascript
  return axios.post(targetUrl, payload);
}

async function fetchViaGot(url: string) {
  // ruleid: ssrf-unchecked-url-javascript
  return got.get(url);
}

function fetchViaHttps(url: string) {
  // ruleid: ssrf-unchecked-url-javascript
  return https.request(url);
}

async function fetchFixedApi() {
  // ok: ssrf-unchecked-url-javascript
  return fetch("https://api.example.com/v1/status");
}

async function fetchChecked(url: string) {
  // ok: ssrf-unchecked-url-javascript
  return fetch(checkPublicUrl(url));
}

async function fetchAsserted(url: string) {
  // ok: ssrf-unchecked-url-javascript
  return axios.get(assertPublicUrl(url));
}

async function fetchGuardedHelper(url: string) {
  // ok: ssrf-unchecked-url-javascript
  return fetch(safeFetch(url));
}
