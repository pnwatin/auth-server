use axum::Router;
use tokio::net::TcpListener;
use tower_http::{
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::Level;

pub struct Application {
    app: Router,
    listener: TcpListener,
}

impl Application {
    pub async fn build() -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:3000").await?;

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
                    .latency_unit(LatencyUnit::Micros),
            )
            .on_failure(DefaultOnFailure::new().level(Level::ERROR));

        let app = Router::new().layer(tracing_layer);

        Ok(Self { app, listener })
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        tracing::debug!("Listening on {}", self.listener.local_addr().unwrap());

        axum::serve(self.listener, self.app.into_make_service()).await
    }
}
