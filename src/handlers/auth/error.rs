use axum::{http::StatusCode, response::IntoResponse};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid token.")]
    InvalidToken,
    #[error("Invalid credentials.")]
    InvalidCredentials,
    #[error("This email is already used.")]
    EmailTaken,

    // opaque errors
    #[error(transparent)]
    DatabaseError(#[from] sqlx::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED).into_response(),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED).into_response(),
            // TODO: mitigate this privacy risk (return 201 and send confirmation mail ?)
            AuthError::EmailTaken => (StatusCode::CONFLICT).into_response(),
            AuthError::DatabaseError(e) => {
                tracing::error!("Database error : {:?}", e);

                (StatusCode::INTERNAL_SERVER_ERROR).into_response()
            }
            AuthError::UnexpectedError(e) => {
                tracing::error!("Unexpected error : {:?}", e);

                (StatusCode::INTERNAL_SERVER_ERROR).into_response()
            }
        }
    }
}
