mod error;
mod sign_in;
mod sign_up;
mod tokens;

use anyhow::Context;
use axum::{routing::post, Router};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
pub use sign_in::Tokens;
use uuid::Uuid;

pub use error::*;

pub fn auth_router() -> Router {
    Router::new()
        .route("/sign-up", post(sign_up::sign_up_handler))
        .route("/sign-in", post(sign_in::sign_in_handler))
        .nest(
            "/tokens",
            Router::new().route("/refresh", post(tokens::refresh_tokens_handler)),
        )
}

pub fn create_access_token(user_id: Uuid, encoding_key: &EncodingKey) -> Result<String, AuthError> {
    let iat = Utc::now().timestamp() as usize;
    let exp = (Utc::now()
        + Duration::try_minutes(10).context("Failed to create access token exp.")?)
    .timestamp() as usize;

    let claims = TokenClaims {
        exp,
        sub: user_id,
        jit: Uuid::new_v4(),
        iat,
    };

    let token = encode(&jsonwebtoken::Header::default(), &claims, encoding_key)
        .context("Failed to encode access token.")?;

    Ok(token)
}

pub fn create_refresh_token(
    user_id: Uuid,
    encoding_key: &EncodingKey,
) -> Result<String, AuthError> {
    let iat = Utc::now().timestamp() as usize;
    let exp = (Utc::now() + Duration::try_days(7).context("Failed to create refresh token exp.")?)
        .timestamp() as usize;

    let claims = TokenClaims {
        exp,
        sub: user_id,
        jit: Uuid::new_v4(),
        iat,
    };

    let token = encode(&jsonwebtoken::Header::default(), &claims, encoding_key)
        .context("Failed to encode refresh token.")?;

    Ok(token)
}

#[derive(Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: Uuid,
    pub jit: Uuid,
    pub iat: usize,
    pub exp: usize,
}

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}
