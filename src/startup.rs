use axum::Router;
use tokio::net::TcpListener;

pub struct Application {
    app: Router,
    listener: TcpListener,
}

impl Application {
    pub async fn build() -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:3000").await?;

        let app = Router::new();

        Ok(Self { app, listener })
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        axum::serve(self.listener, self.app.into_make_service()).await
    }
}
