use anyhow::Context;
use axum::{response::IntoResponse, Extension, Json};
use serde::Deserialize;
use sqlx::PgPool;

use crate::settings::JWTSettings;

use super::{AccessToken, AuthError, RefreshToken, Token, TokensResponse};

pub async fn refresh_tokens_handler(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_settings): Extension<JWTSettings>,
    Json(payload): Json<RefreshTokensPayload>,
) -> Result<impl IntoResponse, AuthError> {
    let keys = jwt_settings.get_keys();

    let refresh_token = RefreshToken::refresh(
        &payload.refresh_token,
        &keys.decoding,
        jwt_settings.refresh_token_exp_seconds,
        &pool,
    )
    .await?;

    let access_token = AccessToken::new(
        refresh_token.claims().sub,
        jwt_settings.refresh_token_exp_seconds,
    )
    .encode(&keys.encoding)
    .context("Couldn't encode access token.")?;

    let refresh_token = refresh_token
        .encode(&keys.encoding)
        .context("Couldn't encode refresh token")?;

    Ok(Json(TokensResponse {
        access_token,
        refresh_token,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokensPayload {
    pub refresh_token: String,
}
