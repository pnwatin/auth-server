use axum::http::StatusCode;

#[tracing::instrument(name = "HANDLER - CHECK HEALTH")]
pub async fn health_check_handler() -> StatusCode {
    StatusCode::OK
}
