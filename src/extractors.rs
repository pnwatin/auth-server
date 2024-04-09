use std::{error::Error, net::SocketAddr};

use axum::{
    async_trait,
    extract::{rejection::JsonRejection, ConnectInfo, FromRequest, FromRequestParts, Request},
    http::header::USER_AGENT,
    response::IntoResponse,
};
use problemdetails::Problem;
use serde::Serialize;

pub struct Json<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for Json<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = Problem;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => Err(match rejection {
                JsonRejection::MissingJsonContentType(err) => problemdetails::new(err.status())
                    .with_title("Invalid Content-Type header.")
                    .with_detail("Content-Type header either missing or invalid - please add `Content-Type: application/json` header."),
                JsonRejection::JsonSyntaxError(err) => problemdetails::new(err.status())
                    .with_title("Invalid json syntax.")
                    .with_detail("Provided json body contains a syntax error - please fix it.")
                    .with_value("error", err.source().map(|e| e.to_string()).unwrap_or_default()),
                JsonRejection::JsonDataError(err) => problemdetails::new(err.status())
                    .with_title("Invalid json data.")
                    .with_detail("Provided json body contains invalid or missing data - please fix it.")
                    .with_value("error", err.source().map(|e| e.to_string()).unwrap_or_default()),
                JsonRejection::BytesRejection(err) => problemdetails::new(err.status()),
                _ => problemdetails::new(rejection.status()),
            }),
        }
    }
}

impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        axum::Json(self.0).into_response()
    }
}

pub struct RequestMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for RequestMetadata
where
    S: Send + Sync,
{
    type Rejection = Problem;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip_address = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .ok()
            .map(|addr| addr.to_string());

        let user_agent = parts
            .headers
            .get(USER_AGENT)
            .and_then(|ua| ua.to_str().ok())
            .map(|ua| ua.to_string());

        Ok(Self {
            ip_address,
            user_agent,
        })
    }
}
