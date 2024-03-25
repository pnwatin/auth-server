use std::net::SocketAddr;

use axum::{routing::get, Extension, Router};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    request_id::MakeRequestUuid,
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
    LatencyUnit, ServiceBuilderExt,
};
use tracing::Level;

use crate::{
    handlers,
    settings::{DatabaseSettings, Settings},
};

pub struct Application {
    app: Router,
    listener: TcpListener,
}

impl Application {
    pub async fn build(settings: Settings) -> Result<Self, std::io::Error> {
        let connection_pool = get_connection_pool(&settings.database);

        let address = format!(
            "{}:{}",
            settings.application.host, settings.application.port
        );

        let listener = TcpListener::bind(address).await?;

        let tracing_layer = TraceLayer::new_for_http()
            .make_span_with(
                DefaultMakeSpan::new()
                    .level(Level::INFO)
                    .include_headers(true),
            )
            .on_response(
                DefaultOnResponse::new()
                    .include_headers(true)
                    .level(Level::INFO)
                    .latency_unit(LatencyUnit::Millis),
            )
            .on_failure(DefaultOnFailure::new().level(Level::ERROR));

        let middleware = ServiceBuilder::new()
            .set_x_request_id(MakeRequestUuid)
            .layer(tracing_layer)
            .propagate_x_request_id();

        let app = Router::new()
            .route("/_health-check", get(handlers::health_check_handler))
            .nest("/auth", handlers::auth_router())
            .layer(middleware)
            .layer(Extension(connection_pool))
            .layer(Extension(settings.jwt));

        Ok(Self { app, listener })
    }

    pub fn address(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        tracing::debug!("Listening on {}", self.listener.local_addr().unwrap());

        axum::serve(self.listener, self.app.into_make_service()).await
    }
}

pub fn get_connection_pool(settings: &DatabaseSettings) -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy_with(settings.with_database())
}
