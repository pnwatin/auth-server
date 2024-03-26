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

    let refresh_token_claims = RefreshToken::decode(&payload.refresh_token, &keys.decoding)
        .map_err(|_| AuthError::InvalidToken)?;

    let user_id = refresh_token_claims.sub;
    let family = refresh_token_claims.family;

    RefreshToken::from(refresh_token_claims)
        .validate(&pool)
        .await?;

    let refresh_token = RefreshToken::new(user_id, family, jwt_settings.refresh_token_exp_seconds)
        .save(&pool)
        .await
        .context("Couldn't save refresh token.")?
        .encode(&keys.encoding)
        .context("Couldn't encode refresh token.")?;

    let access_token = AccessToken::new(user_id, jwt_settings.refresh_token_exp_seconds)
        .encode(&keys.encoding)
        .context("Couldn't encode access token.")?;

    Ok(Json(TokensResponse {
        access_token,
        refresh_token,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokensPayload {
    pub refresh_token: String,
}
