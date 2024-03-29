use axum::{http::StatusCode, response::IntoResponse};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid refresh token.")]
    InvalidRefreshToken,
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
            AuthError::InvalidCredentials => problemdetails::new(StatusCode::UNAUTHORIZED)
                .with_title("Invalid credentials.")
                .with_detail("Provided credentials are invalid - please provide invalid.")
                .into_response(),
            AuthError::InvalidRefreshToken => problemdetails::new(StatusCode::UNAUTHORIZED)
                .with_title("Invalid refresh token.")
                .with_detail("Provided refresh token is invalid - please re-authenticate.")
                .into_response(),
            // TODO: mitigate this privacy risk (return 201 and send confirmation mail ?)
            AuthError::EmailTaken => problemdetails::new(StatusCode::CONFLICT)
                .with_title("Email already used.")
                .with_detail("Provided email is already used - please choose another email.")
                .into_response(),
            AuthError::DatabaseError(e) => {
                tracing::error!("Database error : {:?}", e);

                problemdetails::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .with_title("Something went wrong.")
                    .with_detail("An error occured - please retry later.")
                    .into_response()
            }
            AuthError::UnexpectedError(e) => {
                tracing::error!("Unexpected error : {:?}", e);

                problemdetails::new(StatusCode::INTERNAL_SERVER_ERROR)
                    .with_title("Something went wrong.")
                    .with_detail("An error occured - please retry later.")
                    .into_response()
            }
        }
    }
}
