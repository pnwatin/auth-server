use anyhow::Context;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{response::IntoResponse, Extension};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{domain::Email, extractors::Json, telemetry::spawn_blocking_with_tracing};

use super::{AccessToken, AuthError, RefreshToken, TokensPair, TokensResponse};

#[tracing::instrument(name = "HANDLER - SIGN UP", skip(pool, payload))]
pub async fn sign_in_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<SignInPayload>,
) -> Result<impl IntoResponse, AuthError> {
    let user_id = validate_credentials(payload, &pool).await?;

    let tokens = generate_tokens(user_id, &pool).await?;

    let body = Json(TokensResponse::try_from(tokens).context("Couldn't encode tokens.")?);

    Ok(body)
}

#[tracing::instrument(name = "GENERATE TOKENS", skip(user_id, pool))]
async fn generate_tokens(user_id: Uuid, pool: &PgPool) -> Result<TokensPair, sqlx::Error> {
    let access_token = AccessToken::new(user_id);

    let refresh_token = RefreshToken::new(user_id, Uuid::new_v4())
        .save(pool)
        .await?;

    Ok(TokensPair {
        access_token,
        refresh_token,
    })
}

#[tracing::instrument(name = "VALIDATE CREDENTIALS", skip(credentials, pool))]
async fn validate_credentials(
    credentials: SignInPayload,
    pool: &PgPool,
) -> Result<Uuid, AuthError> {
    let mut user_id = None;
    let mut expected_password_hash = Secret::new(
        "$argon2id$v=19$m=15000,t=2,p=1$\
        gZiV/M1gPc22ElAH/Jh1Hw$\
        CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno"
            .to_string(),
    );

    if let Some((stored_user_id, stored_password_hash)) =
        get_stored_credentials(&credentials.email, pool).await?
    {
        user_id = Some(stored_user_id);
        expected_password_hash = stored_password_hash;
    }

    spawn_blocking_with_tracing(move || {
        verify_password_hash(expected_password_hash, credentials.password)
    })
    .await
    .context("Failed to spawn blocking task.")
    .map_err(AuthError::UnexpectedError)?
    .await?;

    user_id.ok_or_else(|| AuthError::InvalidCredentials)
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
    .await?
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
) -> Result<(), AuthError> {
    let expected_password_hash = PasswordHash::new(expected_password_hash.expose_secret())
        .context("Failed to parse hash in PHC string format.")?;

    Argon2::default()
        .verify_password(
            password_candidate.expose_secret().as_bytes(),
            &expected_password_hash,
        )
        .map_err(|_| AuthError::InvalidCredentials)
}

#[derive(Debug, Deserialize)]
pub struct SignInPayload {
    pub email: Email,
    pub password: Secret<String>,
}
