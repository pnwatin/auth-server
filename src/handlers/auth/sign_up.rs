use axum::{http::StatusCode, response::IntoResponse};

pub async fn sign_up_handler() -> impl IntoResponse {
    StatusCode::OK
}
