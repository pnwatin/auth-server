use axum::{http::StatusCode, response::IntoResponse };

pub async fn sign_in_handler() -> impl IntoResponse {
    StatusCode::OK
}
