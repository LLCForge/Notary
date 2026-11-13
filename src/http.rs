//! Outbound HTTP helpers with bounded response sizes.

use std::time::Duration;

use anyhow::{bail, Context};

pub fn client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("notary/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .context("building HTTP client")
}

/// GETs `url` and returns the body, failing if it exceeds `limit` bytes.
pub async fn get_limited(
    client: &reqwest::Client,
    url: &str,
    limit: u64,
) -> anyhow::Result<Vec<u8>> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    read_limited(resp, url, limit).await
}

/// Reads a successful response body of at most `limit` bytes.
pub async fn read_limited(
    mut resp: reqwest::Response,
    url: &str,
    limit: u64,
) -> anyhow::Result<Vec<u8>> {
    if !resp.status().is_success() {
        bail!("GET {url}: HTTP {}", resp.status());
    }
    if resp.content_length().is_some_and(|n| n > limit) {
        bail!("GET {url}: response larger than {limit} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.with_context(|| format!("GET {url}"))? {
        if body.len() as u64 + chunk.len() as u64 > limit {
            bail!("GET {url}: response larger than {limit} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
