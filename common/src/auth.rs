//! OAuth authentication with PKCE flow and keyring storage

use std::fs::File;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use fs4::fs_std::FileExt;
use oauth2::{
    basic::{
        BasicClient, BasicErrorResponse, BasicRevocationErrorResponse,
        BasicTokenIntrospectionResponse, BasicTokenResponse,
    },
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, RedirectUrl, RefreshToken, Scope, StandardRevocableToken, TokenResponse, TokenUrl,
};
use tokio::sync::oneshot;

use crate::config::OAuthConfig;

const DEFAULT_CALLBACK_PORT: u16 = 19284;
const KEYRING_SERVICE: &str = "webhook-relay";
const KEYRING_ACCESS_TOKEN: &str = "access_token";
const KEYRING_REFRESH_TOKEN: &str = "refresh_token";
const AUTH_LOCK_FILE: &str = "webhook-relay-auth.lock";

// Type alias for our configured client with auth_uri and token_uri set
type ConfiguredClient = oauth2::Client<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,      // HasAuthUrl
    EndpointNotSet,   // HasDeviceAuthUrl
    EndpointNotSet,   // HasIntrospectionUrl
    EndpointNotSet,   // HasRevocationUrl
    EndpointSet,      // HasTokenUrl
>;

/// Guard that holds the auth lock file open, releasing it on drop
struct AuthLockGuard {
    _file: File,
    path: PathBuf,
}

impl Drop for AuthLockGuard {
    fn drop(&mut self) {
        // Lock is automatically released when file is closed
        tracing::debug!("Released auth lock: {:?}", self.path);
    }
}

fn acquire_auth_lock() -> Result<AuthLockGuard> {
    let lock_path = std::env::temp_dir().join(AUTH_LOCK_FILE);

    tracing::debug!("Acquiring auth lock: {:?}", lock_path);

    let file = File::create(&lock_path).context("Failed to create auth lock file")?;

    // Cross-platform file locking via fs4
    file.lock_exclusive()
        .context("Failed to acquire auth lock")?;

    tracing::debug!("Acquired auth lock");

    Ok(AuthLockGuard {
        _file: file,
        path: lock_path,
    })
}

/// OAuth authentication manager with keyring storage
pub struct AuthManager {
    client: ConfiguredClient,
    http_client: reqwest::Client,
    keyring_user: String,
    callback_port: u16,
}

impl AuthManager {
    /// Create a new AuthManager from OAuth configuration
    pub fn new(config: &OAuthConfig) -> Result<Self> {
        let auth_url = config.auth_url.as_ref()
            .context("auth_url is required")?;
        let token_url = config.token_url.as_ref()
            .context("token_url is required")?;
        
        let callback_port = config.callback_port.unwrap_or(DEFAULT_CALLBACK_PORT);
        
        let client = BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_auth_uri(AuthUrl::new(auth_url.clone())?)
            .set_token_uri(TokenUrl::new(token_url.clone())?)
            .set_redirect_uri(RedirectUrl::new(format!("http://localhost:{}/callback", callback_port))?);
        
        // Build HTTP client for oauth2 requests (no redirects for SSRF protection)
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("Failed to build HTTP client")?;
        
        let keyring_user = format!("{}@{}", config.client_id, config.issuer);
        
        Ok(Self {
            client,
            http_client,
            keyring_user,
            callback_port,
        })
    }
    
    /// Get an access token, using stored token if available, otherwise authenticate
    pub async fn get_access_token(&self) -> Result<String> {
        // Try to get stored token
        if let Ok(token) = self.get_stored_token() {
            return Ok(token);
        }
        
        // Try to refresh using stored refresh token
        if let Ok(token) = self.try_refresh_token().await {
            return Ok(token);
        }
        
        // Need to authenticate
        self.authenticate().await
    }
    
    /// Get stored access token from keyring
    fn get_stored_token(&self) -> Result<String> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &format!("{}:{}", self.keyring_user, KEYRING_ACCESS_TOKEN))?;
        entry.get_password().context("No stored access token")
    }
    
    /// Get stored refresh token from keyring
    fn get_stored_refresh_token(&self) -> Result<String> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &format!("{}:{}", self.keyring_user, KEYRING_REFRESH_TOKEN))?;
        entry.get_password().context("No stored refresh token")
    }
    
    /// Try to refresh the access token using stored refresh token
    async fn try_refresh_token(&self) -> Result<String> {
        let refresh_token = self.get_stored_refresh_token()?;
        
        tracing::debug!("Attempting token refresh");
        
        let token_result = self.client
            .exchange_refresh_token(&RefreshToken::new(refresh_token))
            .request_async(&self.http_client)
            .await
            .context("Failed to refresh token")?;
        
        let access_token = token_result.access_token().secret().to_string();
        let refresh_token = token_result.refresh_token().map(|t| t.secret().as_str());
        
        self.store_tokens(&access_token, refresh_token)?;
        
        tracing::info!("Token refreshed successfully");
        
        Ok(access_token)
    }
    
    /// Store tokens in keyring
    fn store_tokens(&self, access_token: &str, refresh_token: Option<&str>) -> Result<()> {
        let access_entry = keyring::Entry::new(
            KEYRING_SERVICE,
            &format!("{}:{}", self.keyring_user, KEYRING_ACCESS_TOKEN),
        )?;
        access_entry.set_password(access_token)?;
        
        if let Some(refresh) = refresh_token {
            let refresh_entry = keyring::Entry::new(
                KEYRING_SERVICE,
                &format!("{}:{}", self.keyring_user, KEYRING_REFRESH_TOKEN),
            )?;
            refresh_entry.set_password(refresh)?;
        }
        
        Ok(())
    }
    
    /// Clear stored tokens from keyring
    pub fn clear_tokens(&self) -> Result<()> {
        if let Ok(entry) = keyring::Entry::new(
            KEYRING_SERVICE,
            &format!("{}:{}", self.keyring_user, KEYRING_ACCESS_TOKEN),
        ) {
            let _ = entry.delete_credential();
        }
        
        if let Ok(entry) = keyring::Entry::new(
            KEYRING_SERVICE,
            &format!("{}:{}", self.keyring_user, KEYRING_REFRESH_TOKEN),
        ) {
            let _ = entry.delete_credential();
        }
        
        Ok(())
    }
    
    /// Perform browser-based OAuth authentication with PKCE
    async fn authenticate(&self) -> Result<String> {
        // Acquire lock to prevent concurrent auth sessions
        let _lock = acquire_auth_lock()
            .context("Another authentication session is in progress. Please wait.")?;
        
        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        
        // Generate authorization URL with offline_access scope for refresh tokens
        let (auth_url, csrf_token) = self.client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("offline_access".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();
        
        println!("Opening browser for authentication...");
        println!("If the browser doesn't open, visit: {}", auth_url);
        
        // Try to open browser
        if let Err(e) = open::that(auth_url.to_string()) {
            tracing::warn!("Failed to open browser: {}", e);
        }
        
        // Start callback server
        let code = self.wait_for_callback(csrf_token).await?;
        
        // Exchange code for tokens
        let token_result = self.client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http_client)
            .await
            .context("Failed to exchange authorization code")?;
        
        let access_token = token_result.access_token().secret().to_string();
        let refresh_token = token_result.refresh_token().map(|t| t.secret().as_str());
        
        self.store_tokens(&access_token, refresh_token)?;
        
        println!("Authenticated successfully.");
        
        Ok(access_token)
    }
    
    /// Wait for OAuth callback on local server
    async fn wait_for_callback(&self, expected_csrf: CsrfToken) -> Result<AuthorizationCode> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.callback_port))
            .context("Failed to bind callback server")?;
        
        let (tx, rx) = oneshot::channel();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        
        // Spawn blocking task to handle the callback
        let tx_clone = tx.clone();
        let expected_csrf_secret = expected_csrf.secret().to_string();
        
        tokio::task::spawn_blocking(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{BufRead, BufReader, Write};

                let mut reader = BufReader::new(&stream);
                let mut request_line = String::new();

                if reader.read_line(&mut request_line).is_ok()
                    && let Some(path) = request_line.split_whitespace().nth(1)
                    && let Some(query) = path.strip_prefix("/callback?")
                {
                    let params: std::collections::HashMap<_, _> = query
                        .split('&')
                        .filter_map(|p| {
                            let mut parts = p.splitn(2, '=');
                            Some((parts.next()?, parts.next()?))
                        })
                        .collect();

                    let code = params.get("code").map(|s| s.to_string());
                    let state = params.get("state").map(|s| s.to_string());

                    // Send response
                    let response = if code.is_some() {
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Authentication successful!</h1><p>You can close this window.</p></body></html>"
                    } else {
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Authentication failed</h1></body></html>"
                    };

                    let _ = stream.write_all(response.as_bytes());

                    if let Some(tx) = tx_clone.lock().unwrap().take() {
                        let _ = tx.send((code, state, expected_csrf_secret));
                    }
                }
            }
        });
        
        let (code, state, expected_csrf_secret) = rx.await
            .context("Callback server failed")?;
        
        let code = code.ok_or_else(|| anyhow::anyhow!("No authorization code received"))?;
        let state = state.ok_or_else(|| anyhow::anyhow!("No state received"))?;
        
        if state != expected_csrf_secret {
            bail!("CSRF token mismatch");
        }
        
        Ok(AuthorizationCode::new(code))
    }
}
