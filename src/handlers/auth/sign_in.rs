use axum::{http::StatusCode, response::IntoResponse, Json};
use secrecy::Secret;
use serde::Deserialize;

use crate::domain::Email;

pub async fn sign_in_handler(Json(_payload): Json<SignInPayload>) -> impl IntoResponse {
    StatusCode::OK
}

#[derive(Deserialize)]
pub struct SignInPayload {
    pub email: Email,
    pub password: Secret<String>,
}
