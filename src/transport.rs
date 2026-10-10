use anyhow::{Context, Result, ensure};
use reqwest::blocking::Client;
use std::{io::Read, time::Duration};
use url::Url;

pub type Params = Vec<(String, String)>;
pub fn params(values: &[(&str, &str)]) -> Params {
    values
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}
pub trait Transport {
    fn post(
        &self,
        server: &str,
        page: &str,
        session_id: Option<&str>,
        values: &Params,
    ) -> Result<Vec<u8>>;
}
pub struct HttpTransport {
    client: Client,
}
impl HttpTransport {
    pub fn new() -> Result<Self> {
        let mut builder = Client::builder()
            .user_agent("LastPass-CLI/1.6.1")
            .timeout(Duration::from_secs(45))
            .connect_timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none());
        // Respect an explicitly configured CA bundle; never disable TLS verification.
        if let Some(path) = std::env::var_os("SSL_CERT_FILE") {
            let pem = std::fs::read(path).context("Could not read configured CA bundle")?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)? {
                builder = builder.add_root_certificate(cert);
            }
        }
        Ok(Self {
            client: builder
                .build()
                .context("Could not initialize HTTPS client")?,
        })
    }
}
pub fn valid_server(server: &str) -> bool {
    if matches!(server, "lastpass.com" | "lastpass.eu") {
        return true;
    }
    // Loopback HTTP is only for explicitly selected integration-test servers.
    Url::parse(server).ok().is_some_and(|u| {
        u.scheme() == "http"
            && matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            && u.username().is_empty()
            && u.password().is_none()
            && u.path() == "/"
            && u.query().is_none()
            && u.fragment().is_none()
    })
}
impl Transport for HttpTransport {
    fn post(
        &self,
        server: &str,
        page: &str,
        session_id: Option<&str>,
        values: &Params,
    ) -> Result<Vec<u8>> {
        ensure!(
            valid_server(server),
            "Refusing to send credentials to an unrecognized LastPass server"
        );
        ensure!(
            !page.starts_with('/') && !page.contains("..") && !page.contains('?'),
            "Invalid endpoint path"
        );
        let base = if server.starts_with("http://") {
            server.trim_end_matches('/').to_owned()
        } else {
            format!("https://{server}")
        };
        let mut request = self.client.post(format!("{base}/{page}")).form(values);
        if let Some(sid) = session_id {
            ensure!(!sid.contains(['\r', '\n', ';']), "Invalid session cookie");
            request = request.header(reqwest::header::COOKIE, format!("PHPSESSID={sid}"));
        }
        let response = request
            .send()
            .with_context(|| format!("Cannot reach LastPass endpoint {page}"))?;
        if page == "logout.php" && response.status().is_redirection() {
            // The supplied libcurl implementation does not follow redirects
            // and accepts 3xx logout responses. Do not forward a token/cookie
            // to the redirect target.
            return Ok(Vec::new());
        }
        ensure!(
            response.status().is_success(),
            "LastPass endpoint {page} returned HTTP {}",
            response.status().as_u16()
        );
        if let Some(n) = response.content_length() {
            ensure!(n <= 64 * 1024 * 1024, "Server response exceeds 64 MiB");
        }
        let mut body = Vec::new();
        response
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut body)
            .context("Cannot read server response")?;
        ensure!(
            body.len() <= 64 * 1024 * 1024,
            "Server response exceeds 64 MiB"
        );
        Ok(body)
    }
}
