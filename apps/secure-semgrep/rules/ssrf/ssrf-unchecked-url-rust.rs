use crate::net::{assert_public_url, safe_fetch};

async fn preview_link(url: &str) -> Result<reqwest::Response, reqwest::Error> {
    // ruleid: ssrf-unchecked-url-rust
    reqwest::get(url).await
}

async fn send_webhook(client: &reqwest::Client, target_url: &str) -> Result<reqwest::Response, reqwest::Error> {
    // ruleid: ssrf-unchecked-url-rust
    client.post(target_url).send().await
}

async fn fetch_fixed_api(client: &reqwest::Client) -> Result<reqwest::Response, reqwest::Error> {
    // ok: ssrf-unchecked-url-rust
    client.get("https://api.example.com/v1/status").send().await
}

async fn fetch_asserted(url: &str) -> Result<reqwest::Response, reqwest::Error> {
    // ok: ssrf-unchecked-url-rust
    reqwest::get(assert_public_url(url)?).await
}

async fn fetch_guarded_helper(url: &str) -> Result<reqwest::Response, reqwest::Error> {
    // ok: ssrf-unchecked-url-rust
    reqwest::get(safe_fetch(url)).await
}
