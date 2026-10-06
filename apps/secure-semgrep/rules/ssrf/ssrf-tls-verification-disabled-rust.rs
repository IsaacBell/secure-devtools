fn insecure_client() -> reqwest::Client {
    // ruleid: ssrf-tls-verification-disabled-rust
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

fn secure_client() -> reqwest::Client {
    // ok: ssrf-tls-verification-disabled-rust
    reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .unwrap()
}

fn default_client() -> reqwest::Client {
    // ok: ssrf-tls-verification-disabled-rust
    reqwest::Client::builder().build().unwrap()
}
