use axum::{http::StatusCode, response::IntoResponse, Extension, Json};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::Email;

pub async fn sign_up_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<SignUpPayload>,
) -> Result<(), SignUpError> {
    let _user_id = insert_user(&payload, &pool).await.map_err(|e| match e {
        sqlx::Error::Database(err) if err.is_unique_violation() => SignUpError::EmailTaken,
        _ => SignUpError::UnexpectedError(e.into()),
    })?;

    Ok(())
}

async fn insert_user(user: &SignUpPayload, pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    let user_id = Uuid::new_v4();

    sqlx::query!(
        r#"
            INSERT INTO users (id, email, password_hash)
            VALUES ($1, $2, $3);
        "#,
        user_id,
        user.email.as_ref(),
        user.password.expose_secret()
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
