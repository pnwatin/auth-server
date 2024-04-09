use anyhow::Context;
use axum::{response::IntoResponse, Extension};
use serde::Deserialize;
use sqlx::PgPool;

use crate::{
    error::AppError,
    extractors::{Json, RequestMetadata},
};

use super::{AccessToken, RefreshToken, Token, TokensPair, TokensResponse};

#[tracing::instrument(name = "HANDLER - REFRESH TOKENS", skip(pool, payload, metadata))]
pub async fn refresh_tokens_handler(
    Extension(pool): Extension<PgPool>,
    metadata: RequestMetadata,
    Json(payload): Json<RefreshTokensPayload>,
) -> Result<impl IntoResponse, AppError> {
    let tokens = refresh_tokens(&payload.refresh_token, &metadata, &pool).await?;

    let body = Json(TokensResponse::try_from(tokens).context("Failed to encode tokens.")?);

    Ok(body)
}

#[tracing::instrument(name = "REFRESH TOKENS", skip(refresh_token, pool, metadata))]
async fn refresh_tokens(
    refresh_token: &str,
    metadata: &RequestMetadata,
    pool: &PgPool,
) -> Result<TokensPair, AppError> {
    let refresh_token_claims =
        RefreshToken::decode(refresh_token).map_err(|_| AppError::InvalidRefreshToken)?;

    let user_id = refresh_token_claims.sub;
    let family = refresh_token_claims.family;

    RefreshToken::from(refresh_token_claims)
        .validate(pool)
        .await
        .context("Failed to execute query.")?
        .ok_or(AppError::InvalidRefreshToken)?;

    let refresh_token = RefreshToken::new(user_id, family)
        .save(metadata, pool)
        .await?;

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
