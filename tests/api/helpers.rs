use std::net::SocketAddr;

use matoscout_api::{
    settings::{get_settings, DatabaseSettings},
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};
use once_cell::sync::Lazy;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

static TRACING: Lazy<()> = Lazy::new(|| {
    let env_filter = EnvFilter::new("trace");

    if std::env::var("TEST_LOG").is_ok() {
        let subscriber = get_subscriber(env_filter, std::io::stdout);
        init_subscriber(subscriber);
    } else {
        let subscriber = get_subscriber(env_filter, std::io::sink);
        init_subscriber(subscriber);
    }
});

pub struct TestApplication {
    pub address: SocketAddr,
    pub base_url: String,
    pub pool: PgPool,
}

impl TestApplication {
    pub async fn spawn() -> Self {
        Lazy::force(&TRACING);

        let settings = {
            let mut settings = get_settings().expect("Failed to get configuration.");

            settings.database.database_name = Uuid::new_v4().to_string();
            settings.application.port = 0;

            settings
        };

        let pool = get_connection_pool(&settings.database).await;

        let application = Application::build(settings)
            .await
            .expect("Failed to build application.");

        let address = application
            .address()
            .expect("Failed to get application address.");

        let ip = address.ip();
        let port = address.port();

        let base_url = format!("http://{}:{}", ip, port);

        tokio::spawn(application.run_until_stopped());

        Self {
            address,
            base_url,
            pool,
        }
    }

    pub fn client(&self) -> reqwest::Client {
        reqwest::Client::new()
    }

    pub fn format_url(&self, path: impl Into<String>) -> String {
        format!("{}{}", self.base_url, path.into())
    }

    pub fn get(&self, path: impl Into<String>) -> reqwest::RequestBuilder {
        self.client().get(self.format_url(path))
    }

    pub fn post(&self, path: impl Into<String>) -> reqwest::RequestBuilder {
        self.client().post(self.format_url(path))
    }
}

pub async fn get_connection_pool(database_settings: &DatabaseSettings) -> PgPool {
    let mut connection = PgConnection::connect_with(&database_settings.without_database())
        .await
        .expect("Failed to connect to Postgres.");

    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, database_settings.database_name).as_str())
        .await
        .expect("Failed to create database");

    let connection_pool = PgPool::connect_with(database_settings.with_database())
        .await
        .expect("Failed to connect to Postgres.");

    sqlx::migrate!("./migrations")
        .run(&connection_pool)
        .await
        .expect("Failed to apply migrations to the database.");

    connection_pool
}
