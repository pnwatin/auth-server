use std::net::SocketAddr;

use auth_server::{
    settings::{get_settings, DatabaseSettings},
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};
use fake::{Fake, Faker};
use once_cell::sync::Lazy;
use secrecy::SecretString;
use serde_json::{json, Value};
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
    pub test_user: TestUser,
}

pub struct TestUser {
    pub email: String,
    pub password: String,
}

impl TestApplication {
    pub async fn spawn() -> Self {
        std::env::set_var("APP_ENVIRONMENT", "test");
        Lazy::force(&TRACING);

        let settings = {
            let mut settings = get_settings().expect("Failed to get configuration.");

            settings.database.database_name = Uuid::new_v4().to_string();
            settings.application.port = 0;
            settings.jwt.secret = SecretString::from(Faker.fake::<String>());

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
            test_user: TestUser {
                email: "test@domain.com".into(),
                password: "password".into(),
            },
        }
    }

    pub fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .local_address(self.address.ip())
            .build()
            .expect("Failed to build client")
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

    pub async fn sign_in(&self) -> reqwest::Response {
        self.sign_in_with_payload(&json!({
            "email": self.test_user.email,
            "password": self.test_user.password
        }))
        .await
    }

    pub async fn sign_in_with_payload(&self, payload: &Value) -> reqwest::Response {
        self.post("/auth/sign-in")
            .json(payload)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn sign_up(&self) -> reqwest::Response {
        self.sign_up_with_payload(&json!({
        "email": self.test_user.email,
        "password": self.test_user.password
        }))
        .await
    }

    pub async fn sign_up_with_payload(&self, payload: &Value) -> reqwest::Response {
        self.post("/auth/sign-up")
            .json(payload)
            .send()
            .await
            .expect("Failed to execute request.")
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
