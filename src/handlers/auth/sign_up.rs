use anyhow::Context;
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use axum::{http::StatusCode, response::IntoResponse, Extension, Json};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::Email;

#[tracing::instrument(name = "SIGN UP", skip(pool, payload))]
pub async fn sign_up_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<SignUpPayload>,
) -> Result<(), SignUpError> {
    let password_salt = SaltString::generate(rand::thread_rng());
    let password_hash = Secret::new(
        Argon2::default()
            .hash_password(payload.password.expose_secret().as_bytes(), &password_salt)
            .with_context(|| "Failed to hash password.")
            .map_err(SignUpError::UnexpectedError)?
            .to_string(),
    );

    let _user_id = insert_user(&payload.email, password_hash, &pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(err) if err.is_unique_violation() => SignUpError::EmailTaken,
            _ => SignUpError::UnexpectedError(e.into()),
        })?;

    Ok(())
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
    .await
    .map_err(|e| {
        tracing::error!("Failed to execute query : {:?}", e);
        e
    })?;

    Ok(user_id)
}

#[derive(Debug, thiserror::Error)]
pub enum SignUpError {
    #[error("This email is already used.")]
    EmailTaken,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl IntoResponse for SignUpError {
    fn into_response(self) -> axum::response::Response {
        match self {
            SignUpError::EmailTaken => (StatusCode::CONFLICT).into_response(),
            SignUpError::UnexpectedError(_) => (StatusCode::INTERNAL_SERVER_ERROR).into_response(),
        }
    }
}

#[derive(Deserialize)]
pub struct SignUpPayload {
    pub email: Email,
    pub password: Secret<String>,
}
