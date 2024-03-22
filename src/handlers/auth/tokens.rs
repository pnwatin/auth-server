
use axum::{http::StatusCode, response::IntoResponse };

pub async fn refresh_tokens_handler() -> impl IntoResponse {
    StatusCode::OK
}
