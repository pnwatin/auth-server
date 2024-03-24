mod error;
mod sign_in;
mod sign_up;
mod tokens;

use axum::{routing::post, Router};
use jsonwebtoken::{DecodingKey, EncodingKey};
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
