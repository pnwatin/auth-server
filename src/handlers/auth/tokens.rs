use anyhow::Context;
use axum::{response::IntoResponse, Extension, Json};
use serde::Deserialize;
use sqlx::PgPool;

use crate::settings::JWTSettings;

use super::{AccessToken, AuthError, RefreshToken, Token, TokensPair, TokensResponse};

#[tracing::instrument(name = "HANDLER - REFRESH TOKENS", skip(pool, jwt_settings, payload))]
pub async fn refresh_tokens_handler(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_settings): Extension<JWTSettings>,
    Json(payload): Json<RefreshTokensPayload>,
) -> Result<impl IntoResponse, AuthError> {
    let tokens = refresh_tokens(&payload.refresh_token, &jwt_settings, &pool).await?;

    let body = Json(TokensResponse::try_from(tokens).context("Failed to encode tokens.")?);

    Ok(body)
}

#[tracing::instrument(name = "REFRESH TOKENS", skip(refresh_token, jwt_settings, pool))]
async fn refresh_tokens(
    refresh_token: &str,
    jwt_settings: &JWTSettings,
    pool: &PgPool,
) -> Result<TokensPair, AuthError> {
    let keys = jwt_settings.get_keys();

    let refresh_token_claims =
        RefreshToken::decode(refresh_token, &keys.decoding).map_err(|_| AuthError::InvalidToken)?;

    let user_id = refresh_token_claims.sub;
    let family = refresh_token_claims.family;

    RefreshToken::from(refresh_token_claims)
        .validate(pool)
        .await?;

    let refresh_token = RefreshToken::new(user_id, family, jwt_settings.refresh_token_exp_seconds)
        .save(pool)
        .await
        .context("Couldn't save refresh token.")?;

    let access_token = AccessToken::new(user_id, jwt_settings.refresh_token_exp_seconds);

    Ok(TokensPair {
        access_token,
        refresh_token,
        keys,
    })
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokensPayload {
    pub refresh_token: String,
}
