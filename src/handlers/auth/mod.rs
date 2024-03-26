mod error;
mod sign_in;
mod sign_up;
mod tokens;

use anyhow::Context;
use axum::{routing::post, Router};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, Header, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

pub use error::*;

use crate::settings::JWT_CONFIG;

pub fn auth_router() -> Router {
    Router::new()
        .route("/sign-up", post(sign_up::sign_up_handler))
        .route("/sign-in", post(sign_in::sign_in_handler))
        .nest(
            "/tokens",
            Router::new().route("/refresh", post(tokens::refresh_tokens_handler)),
        )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub jit: Uuid,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RefreshTokenClaims {
    pub sub: Uuid,
    pub family: Uuid,
    pub jit: Uuid,
    pub iat: i64,
    pub exp: i64,
}

pub trait Token<T>: Sized
where
    T: Serialize + DeserializeOwned,
{
    fn encode(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let token = encode(
            &Header::default(),
            &self.claims(),
            &JWT_CONFIG.keys.encoding,
        )?;

        Ok(token)
    }

    fn decode(token: &str) -> Result<T, jsonwebtoken::errors::Error> {
        let token_data = decode::<T>(token, &JWT_CONFIG.keys.decoding, &Validation::default())?;

        Ok(token_data.claims)
    }

    fn decode_with_validation(
        token: &str,
        validation: &Validation,
    ) -> Result<T, jsonwebtoken::errors::Error> {
        let token_data = decode::<T>(token, &JWT_CONFIG.keys.decoding, validation)?;

        Ok(token_data.claims)
    }

    fn claims(&self) -> &T;
}

pub struct RefreshToken(RefreshTokenClaims);

impl RefreshToken {
    pub fn new(user_id: Uuid, family: Uuid) -> Self {
        let iat = Utc::now().timestamp();
        let exp = iat + JWT_CONFIG.refresh_token_exp_seconds;

        let claims = RefreshTokenClaims {
            iat,
            exp,
            sub: user_id,
            family,
            jit: Uuid::new_v4(),
        };

        Self(claims)
    }

    pub async fn save(self, pool: &PgPool) -> Result<Self, sqlx::Error> {
        let claims = self.claims();

        let expires_at = DateTime::from_timestamp(claims.exp, 0);

        sqlx::query!(
            r#"
                INSERT INTO refresh_tokens (id, user_id, jit, family, expires_at, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (family) DO UPDATE
                SET jit = EXCLUDED.jit,
                    expires_at = EXCLUDED.expires_at,
                    created_at = EXCLUDED.created_at;
            "#,
            Uuid::new_v4(),
            claims.sub,
            claims.jit,
            claims.family,
            expires_at,
            Utc::now()
        )
        .execute(pool)
        .await?;

        Ok(self)
    }

    pub async fn validate(self, pool: &PgPool) -> Result<Self, AuthError> {
        let result = sqlx::query!(
            r#"
                SELECT * FROM refresh_tokens WHERE jit = $1; 
            "#,
            self.claims().jit
        )
        .fetch_optional(pool)
        .await
        .context("Failed to fetch execute query")?;

        if result.is_none() {
            sqlx::query!(
                r#"
                    DELETE FROM refresh_tokens WHERE family = $1;
                "#,
                self.claims().family
            )
            .execute(pool)
            .await
            .context("Couldn't delete invalid token family.")?;

            return Err(AuthError::InvalidToken);
        }

        Ok(self)
    }
}

impl From<RefreshTokenClaims> for RefreshToken {
    fn from(value: RefreshTokenClaims) -> Self {
        Self(value)
    }
}

impl Token<RefreshTokenClaims> for RefreshToken {
    fn claims(&self) -> &RefreshTokenClaims {
        &self.0
    }
}

pub struct AccessToken(AccessTokenClaims);

impl AccessToken {
    pub fn new(user_id: Uuid) -> Self {
        let iat = Utc::now().timestamp();
        let exp = iat + JWT_CONFIG.access_token_exp_seconds;

        let claims = AccessTokenClaims {
            iat,
            exp,
            sub: user_id,
            jit: Uuid::new_v4(),
        };

        Self(claims)
    }
}

impl From<AccessTokenClaims> for AccessToken {
    fn from(value: AccessTokenClaims) -> Self {
        Self(value)
    }
}

impl Token<AccessTokenClaims> for AccessToken {
    fn claims(&self) -> &AccessTokenClaims {
        &self.0
    }
}

struct TokensPair {
    pub access_token: AccessToken,
    pub refresh_token: RefreshToken,
}

#[derive(Serialize, Deserialize)]
pub struct TokensResponse {
    pub access_token: String,
    pub refresh_token: String,
}

impl TryFrom<TokensPair> for TokensResponse {
    type Error = jsonwebtoken::errors::Error;
    fn try_from(value: TokensPair) -> Result<Self, Self::Error> {
        let access_token = value.access_token.encode()?;
        let refresh_token = value.refresh_token.encode()?;

        Ok(Self {
            access_token,
            refresh_token,
        })
    }
}
