use anyhow::Context;
use axum::{response::IntoResponse, Extension, Json};
use serde::Deserialize;
use sqlx::PgPool;

use super::{AccessToken, AuthError, RefreshToken, Token, TokensPair, TokensResponse};

#[tracing::instrument(name = "HANDLER - REFRESH TOKENS", skip(pool, payload))]
pub async fn refresh_tokens_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<RefreshTokensPayload>,
) -> Result<impl IntoResponse, AuthError> {
    let tokens = refresh_tokens(&payload.refresh_token, &pool).await?;

    let body = Json(TokensResponse::try_from(tokens).context("Failed to encode tokens.")?);

    Ok(body)
}

#[tracing::instrument(name = "REFRESH TOKENS", skip(refresh_token, pool))]
async fn refresh_tokens(refresh_token: &str, pool: &PgPool) -> Result<TokensPair, AuthError> {
    let refresh_token_claims =
        RefreshToken::decode(refresh_token).map_err(|_| AuthError::InvalidToken)?;

    let user_id = refresh_token_claims.sub;
    let family = refresh_token_claims.family;

    RefreshToken::from(refresh_token_claims)
        .validate(pool)
        .await?;

    let refresh_token = RefreshToken::new(user_id, family)
        .save(pool)
        .await
        .context("Couldn't save refresh token.")?;

    let access_token = AccessToken::new(user_id);

    Ok(TokensPair {
        access_token,
        refresh_token,
    })
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokensPayload {
    pub refresh_token: String,
}
