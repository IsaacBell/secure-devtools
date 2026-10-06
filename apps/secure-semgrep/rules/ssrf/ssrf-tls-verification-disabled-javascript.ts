import https from "node:https";
import axios from "axios";

function insecureAgent() {
  // ruleid: ssrf-tls-verification-disabled-javascript
  return new https.Agent({ rejectUnauthorized: false });
}

function insecureAxiosInstance() {
  // ruleid: ssrf-tls-verification-disabled-javascript
  return axios.create({ rejectUnauthorized: false, timeout: 5000 });
}

function secureAgent() {
  // ok: ssrf-tls-verification-disabled-javascript
  return new https.Agent({ rejectUnauthorized: true });
}

function secureAxiosInstance() {
  // ok: ssrf-tls-verification-disabled-javascript
  return axios.create({ timeout: 5000 });
}
