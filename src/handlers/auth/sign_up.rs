use anyhow::Context;
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use axum::{http::StatusCode, response::IntoResponse, Extension};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{domain::Email, error::AppError, extractors::Json};

#[tracing::instrument(name = "HANDLER - SIGN UP", skip(pool, payload))]
pub async fn sign_up_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<SignUpPayload>,
) -> Result<impl IntoResponse, AppError> {
    let password_hash = hash_password(payload.password).context("Failed to hash password.")?;

    insert_user(&payload.email, password_hash, &pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(err) if err.is_unique_violation() => AppError::EmailTaken,
            e => e.into(),
        })?;

    Ok(StatusCode::CREATED)
}

#[tracing::instrument(name = "INSERT NEW USER", skip(email, password_hash, pool))]
async fn insert_user(
    email: &Email,
    password_hash: Secret<String>,
    pool: &PgPool,
) -> Result<Uuid, sqlx::Error> {
    let user_id = Uuid::new_v4();

    sqlx::query!(
        r#"
            INSERT INTO users (id, email, password_hash)
            VALUES ($1, $2, $3);
        "#,
        user_id,
        email.as_ref(),
        password_hash.expose_secret()
    )
    .execute(pool)
    .await?;

    Ok(user_id)
}

#[tracing::instrument(name = "HASH PASSWORD", skip(password))]
pub fn hash_password(
    password: Secret<String>,
) -> Result<Secret<String>, argon2::password_hash::Error> {
    let password_salt = SaltString::generate(rand::thread_rng());
    let password_hash = Secret::new(
        Argon2::default()
            .hash_password(password.expose_secret().as_bytes(), &password_salt)?
            .to_string(),
    );

    Ok(password_hash)
}

#[derive(Deserialize)]
pub struct SignUpPayload {
    pub email: Email,
    pub password: Secret<String>,
}
