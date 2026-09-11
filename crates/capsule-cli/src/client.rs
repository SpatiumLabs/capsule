use capsule_core::{PageResponse, SandboxInfo, SandboxSpec, SshInfo};
use reqwest::Client;

pub(crate) struct ApiClient {
    client: Client,
    base_url: String,
    token: String,
}

impl ApiClient {
    pub(crate) fn new(base_url: String, token: String) -> Self {
        let client = Client::new();
        Self {
            client,
            base_url,
            token,
        }
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    pub(crate) async fn create_sandbox(&self, spec: &SandboxSpec) -> Result<SandboxInfo, String> {
        let resp = self
            .client
            .post(format!("{}/v1/sandboxes", self.base_url))
            .header("Authorization", self.auth_header())
            .json(spec)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn list_sandboxes(
        &self,
        limit: usize,
    ) -> Result<PageResponse<SandboxInfo>, String> {
        let url = format!("{}/v1/sandboxes?limit={}", self.base_url, limit);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn get_sandbox(&self, id: &str) -> Result<SandboxInfo, String> {
        let resp = self
            .client
            .get(format!("{}/v1/sandboxes/{id}", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) async fn ssh_info(&self, id: &str) -> Result<SshInfo, String> {
        let resp = self
            .client
            .get(format!("{}/v1/sandboxes/{id}/ssh", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("API error: {body}"));
        }

        resp.json().await.map_err(|e| format!("decode failed: {e}"))
    }

    pub(crate) fn ws_url(&self) -> String {
        self.base_url
            .replace("http://", "ws://")
            .replace("https://", "wss://")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_converts_http() {
        let client = ApiClient::new("http://example.com:8080".into(), "t".into());
        assert_eq!(client.ws_url(), "ws://example.com:8080");
    }

    #[test]
    fn ws_url_converts_https() {
        let client = ApiClient::new("https://api.example.com".into(), "t".into());
        assert_eq!(client.ws_url(), "wss://api.example.com");
    }

    #[test]
    fn token_returns_configured_token() {
        let client = ApiClient::new("http://localhost".into(), "my-token".into());
        assert_eq!(client.token(), "my-token");
    }
}
