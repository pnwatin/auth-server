use std::net::SocketAddr;

use fake::{Fake, Faker};
use matoscout_api::{
    settings::{get_settings, DatabaseSettings, JWTSettings},
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};
use once_cell::sync::Lazy;
use secrecy::Secret;
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
    pub jwt_settings: JWTSettings,
}

pub struct TestApplicationSettings {
    pub access_token_exp_seconds: i64,
    pub refresh_token_exp_seconds: i64,
}

impl TestApplication {
    pub async fn run(additionnal_settings: Option<TestApplicationSettings>) -> Self {
        Lazy::force(&TRACING);

        let settings = {
            let mut settings = get_settings().expect("Failed to get configuration.");

            settings.database.database_name = Uuid::new_v4().to_string();
            settings.application.port = 0;
            settings.jwt.secret = Secret::new(Faker.fake());

            if let Some(additionnal_settings) = additionnal_settings {
                settings.jwt.access_token_exp_seconds =
                    additionnal_settings.access_token_exp_seconds;
                settings.jwt.refresh_token_exp_seconds =
                    additionnal_settings.refresh_token_exp_seconds;
            }

            settings
        };

        let pool = get_connection_pool(&settings.database).await;

        let jwt_settings = settings.jwt.clone();

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
            jwt_settings,
        }
    }
    pub async fn spawn() -> Self {
        TestApplication::run(None).await
    }

    pub async fn spawn_with_settings(settings: TestApplicationSettings) -> Self {
        TestApplication::run(Some(settings)).await
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
