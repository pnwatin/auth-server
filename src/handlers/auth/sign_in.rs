use anyhow::Context;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{http::StatusCode, response::IntoResponse, Extension, Json};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{domain::Email, telemetry::spawn_blocking_with_tracing};

#[tracing::instrument(name = "SIGN IN", skip(payload))]
pub async fn sign_in_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<SignInPayload>,
) -> Result<(), SignInError> {
    validate_credentials(payload, &pool).await?;

    Ok(())
}

#[tracing::instrument(name = "VALIDATE CREDENTIALS", skip(credentials, pool))]
async fn validate_credentials(
    credentials: SignInPayload,
    pool: &PgPool,
) -> Result<Uuid, SignInError> {
    let mut user_id = None;
    let mut expected_password_hash = Secret::new(
        "$argon2id$v=19$m=15000,t=2,p=1$\
        gZiV/M1gPc22ElAH/Jh1Hw$\
        CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno"
            .to_string(),
    );

    if let Some((stored_user_id, stored_password_hash)) =
        get_stored_credentials(&credentials.email, pool)
            .await
            .context("Failed to execute query.")
            .map_err(SignInError::UnexpectedError)?
    {
        user_id = Some(stored_user_id);
        expected_password_hash = stored_password_hash;
    }

    spawn_blocking_with_tracing(move || {
        verify_password_hash(expected_password_hash, credentials.password)
    })
    .await
    .context("Failed to spawn blocking task.")
    .map_err(SignInError::UnexpectedError)?
    .await?;

    user_id.ok_or_else(|| SignInError::InvalidCredentials(anyhow::anyhow!("Invalid email.")))
}

#[tracing::instrument(name = "GET STORED CREDENTIALS", skip(email, pool))]
async fn get_stored_credentials(
    email: &Email,
    pool: &PgPool,
) -> Result<Option<(Uuid, Secret<String>)>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
            SELECT id, password_hash
            FROM users
            WHERE email = $1;
        "#,
        email.as_ref()
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to execute query : {:?}", e);
        e
    })?
    .map(|row| (row.id, Secret::new(row.password_hash)));

    Ok(row)
}

#[tracing::instrument(
    name = "VERIFY PASSWORD HASH",
    skip(expected_password_hash, password_candidate)
)]
async fn verify_password_hash(
    expected_password_hash: Secret<String>,
    password_candidate: Secret<String>,
) -> Result<(), SignInError> {
    let expected_password_hash = PasswordHash::new(expected_password_hash.expose_secret())
        .context("Failed to parse hash in PHC string format.")
        .map_err(SignInError::UnexpectedError)?;

    Argon2::default()
        .verify_password(
            password_candidate.expose_secret().as_bytes(),
            &expected_password_hash,
        )
        .context("Invalid password.")
        .map_err(SignInError::InvalidCredentials)
}

#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    #[error("Invalid credentials")]
    InvalidCredentials(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl IntoResponse for SignInError {
    fn into_response(self) -> axum::response::Response {
        match self {
            SignInError::InvalidCredentials(_) => (StatusCode::UNAUTHORIZED).into_response(),
            SignInError::UnexpectedError(_) => (StatusCode::INTERNAL_SERVER_ERROR).into_response(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SignInPayload {
    pub email: Email,
    pub password: Secret<String>,
}
