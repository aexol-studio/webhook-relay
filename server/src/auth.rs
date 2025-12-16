use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{JwkSet, AlgorithmParameters},
};
use serde::Deserialize;
use tokio::sync::RwLock;
use tonic::{Request, Status};

use crate::config::Config;

// =============================================================================
// Claims Types
// =============================================================================

/// Audience can be a single string or array of strings in JWT
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Audience::Single(s) => s == value,
            Audience::Multiple(v) => v.iter().any(|s| s == value),
        }
    }
}

/// Standard JWT claims (RFC 7519 compliant)
#[derive(Debug, Deserialize)]
pub struct StandardClaims {
    pub sub: String,
    pub exp: usize,
    pub iss: String,
    pub aud: Audience,
}

/// Keycloak-specific JWT claims
/// Keycloak access tokens use `azp` (authorized party) instead of `aud`
/// and `preferred_username` instead of `sub` for user identification
#[derive(Debug, Deserialize)]
pub struct KeycloakClaims {
    pub exp: usize,
    pub iss: String,
    /// Authorized party - the client that requested the token
    pub azp: String,
    /// Preferred username for user identification
    pub preferred_username: String,
    /// Session ID
    #[serde(default)]
    pub sid: Option<String>,
    /// Scope
    #[serde(default)]
    pub scope: Option<String>,
}

/// Unified claims enum that can represent different IdP token formats
#[derive(Debug)]
pub enum Claims {
    Standard(StandardClaims),
    Keycloak(KeycloakClaims),
}

impl Claims {
    /// Get the user identifier from the claims
    pub fn user_id(&self) -> &str {
        match self {
            Claims::Standard(c) => &c.sub,
            Claims::Keycloak(c) => &c.preferred_username,
        }
    }

    /// Get the issuer
    pub fn issuer(&self) -> &str {
        match self {
            Claims::Standard(c) => &c.iss,
            Claims::Keycloak(c) => &c.iss,
        }
    }

    /// Check if audience/authorized party matches expected value
    pub fn verify_audience(&self, expected: &str) -> bool {
        match self {
            Claims::Standard(c) => c.aud.contains(expected),
            Claims::Keycloak(c) => c.azp == expected,
        }
    }
}

// =============================================================================
// JWKS Cache
// =============================================================================

struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
}

pub struct JwksCache {
    cache: RwLock<Option<CachedJwks>>,
    jwks_url: String,
    refresh_duration: Duration,
    jwt_issuer: String,
    jwt_audience: String,
}

impl JwksCache {
    pub fn new(config: &Config) -> Self {
        Self {
            cache: RwLock::new(None),
            jwks_url: config.jwks_url.clone(),
            refresh_duration: Duration::from_secs(config.jwks_refresh_secs),
            jwt_issuer: config.jwt_issuer.clone(),
            jwt_audience: config.jwt_audience.clone(),
        }
    }
    
    async fn fetch_jwks(&self) -> Result<JwkSet> {
        let client = reqwest::Client::new();
        let response = client
            .get(&self.jwks_url)
            .send()
            .await
            .context("Failed to fetch JWKS")?;
        
        if !response.status().is_success() {
            bail!("JWKS fetch failed with status: {}", response.status());
        }
        
        response
            .json::<JwkSet>()
            .await
            .context("Failed to parse JWKS")
    }
    
    async fn get_jwks(&self) -> Result<JwkSet> {
        // Check if we have a valid cached JWKS
        {
            let cache = self.cache.read().await;
            if let Some(ref cached) = *cache
                && cached.fetched_at.elapsed() < self.refresh_duration
            {
                return Ok(cached.jwks.clone());
            }
        }
        
        // Need to refresh
        let jwks = self.fetch_jwks().await?;
        
        let mut cache = self.cache.write().await;
        *cache = Some(CachedJwks {
            jwks: jwks.clone(),
            fetched_at: Instant::now(),
        });
        
        Ok(jwks)
    }
    
    pub async fn validate_token(&self, token: &str) -> Result<Claims, Status> {
        let header = decode_header(token)
            .map_err(|e| Status::unauthenticated(format!("Invalid token header: {}", e)))?;
        
        let kid = header.kid
            .ok_or_else(|| Status::unauthenticated("Token missing kid header"))?;
        
        let jwks = self.get_jwks().await
            .map_err(|e| Status::internal(format!("Failed to get JWKS: {}", e)))?;
        
        let jwk = jwks.find(&kid)
            .ok_or_else(|| Status::unauthenticated("Key not found in JWKS"))?;
        
        let decoding_key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
                    .map_err(|e| Status::internal(format!("Invalid RSA key: {}", e)))?
            }
            AlgorithmParameters::EllipticCurve(ec) => {
                DecodingKey::from_ec_components(&ec.x, &ec.y)
                    .map_err(|e| Status::internal(format!("Invalid EC key: {}", e)))?
            }
            _ => return Err(Status::internal("Unsupported key algorithm")),
        };
        
        let algorithm = header.alg;
        if !matches!(algorithm, Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::ES256 | Algorithm::ES384) {
            return Err(Status::unauthenticated("Unsupported token algorithm"));
        }
        
        // Build validation - only validate issuer and expiry, we'll check audience manually
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&self.jwt_issuer]);
        validation.validate_aud = false;
        
        // Try parsing as Keycloak claims first (more specific), then fall back to standard
        let claims = self.try_parse_keycloak(token, &decoding_key, &validation)
            .or_else(|_| self.try_parse_standard(token, &decoding_key, &validation))?;

        // Verify audience
        if !claims.verify_audience(&self.jwt_audience) {
            return Err(Status::unauthenticated("Token audience mismatch"));
        }

        Ok(claims)
    }
    
    fn try_parse_keycloak(
        &self,
        token: &str,
        decoding_key: &DecodingKey,
        validation: &Validation,
    ) -> Result<Claims, Status> {
        let token_data = decode::<KeycloakClaims>(token, decoding_key, validation)
            .map_err(|e| Status::unauthenticated(format!("Keycloak token parse failed: {}", e)))?;
        
        Ok(Claims::Keycloak(token_data.claims))
    }
    
    fn try_parse_standard(
        &self,
        token: &str,
        decoding_key: &DecodingKey,
        validation: &Validation,
    ) -> Result<Claims, Status> {
        let token_data = decode::<StandardClaims>(token, decoding_key, validation)
            .map_err(|e| Status::unauthenticated(format!("Standard token parse failed: {}", e)))?;
        
        Ok(Claims::Standard(token_data.claims))
    }
}

// =============================================================================
// Auth Middleware Helpers
// =============================================================================

pub fn check_auth<T>(_jwks_cache: Arc<JwksCache>) -> impl Fn(Request<T>) -> Result<Request<T>, Status> + Clone {
    move |mut request: Request<T>| {
        let auth_header = request
            .metadata()
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("Missing authorization header"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Invalid authorization header"))?
            .to_string();
        
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| Status::unauthenticated("Invalid authorization format, expected Bearer token"))?
            .to_string();
        
        // Store token in extensions for async validation later
        request.extensions_mut().insert(AuthToken(token));
        
        Ok(request)
    }
}

#[derive(Clone)]
pub struct AuthToken(pub String);

pub async fn validate_auth<T>(request: &Request<T>, jwks_cache: &JwksCache) -> Result<Claims, Status> {
    let token = request
        .extensions()
        .get::<AuthToken>()
        .ok_or_else(|| Status::unauthenticated("No auth token found"))?;
    
    jwks_cache.validate_token(&token.0).await
}
