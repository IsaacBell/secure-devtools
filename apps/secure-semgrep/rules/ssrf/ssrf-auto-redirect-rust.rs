fn client_following_redirects() -> reqwest::Client {
    // ruleid: ssrf-auto-redirect-rust
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .unwrap()
}

fn client_no_auto_redirect() -> reqwest::Client {
    // ok: ssrf-auto-redirect-rust
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}
