use axum::http::StatusCode;

#[tracing::instrument(name = "CHECK HEALTH")]
pub async fn health_check_handler() -> StatusCode {
    StatusCode::OK
}
