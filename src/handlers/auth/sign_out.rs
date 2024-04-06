use axum::{response::IntoResponse, Extension, Json};
use serde::Deserialize;
use sqlx::PgPool;

use crate::error::AppError;

use super::{RefreshToken, Token};

#[tracing::instrument(name = "HANDLER - SIGN OUT", skip(pool, payload))]
pub async fn sign_out_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<SignOutPayload>,
) -> Result<impl IntoResponse, AppError> {
    let refresh_token_claims =
        RefreshToken::decode(&payload.refresh_token).map_err(|_| AppError::InvalidRefreshToken)?;

    RefreshToken::from(refresh_token_claims)
        .invalidate_family(&pool)
        .await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct SignOutPayload {
    pub refresh_token: String,
}
