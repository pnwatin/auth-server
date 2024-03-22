use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::domain::Email;

pub async fn sign_up_handler(Json(_payload): Json<SignUpPayload>) -> impl IntoResponse {
    StatusCode::OK
}

#[derive(Deserialize)]
pub struct SignUpPayload {
    pub email: Email,
    pub password: String,
}
