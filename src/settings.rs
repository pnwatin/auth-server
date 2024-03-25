use jsonwebtoken::{DecodingKey, EncodingKey};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use serde_aux::field_attributes::deserialize_number_from_string;
use sqlx::{postgres::PgConnectOptions, ConnectOptions};
use tracing_log::log::LevelFilter;

#[derive(Deserialize)]
pub struct Settings {
    pub database: DatabaseSettings,
    pub application: ApplicationSettings,
    pub jwt: JWTSettings,
}

#[derive(Deserialize, Clone)]
pub struct JWTSettings {
    pub secret: Secret<String>,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub access_token_exp_seconds: i64,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub refresh_token_exp_seconds: i64,
}

pub struct JWTKeys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl JWTSettings {
    pub fn get_keys(&self) -> JWTKeys {
        let secret = self.secret.expose_secret().as_bytes();

        JWTKeys {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Deserialize)]
pub struct ApplicationSettings {
    pub host: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
}

#[derive(Deserialize)]
pub struct DatabaseSettings {
    pub host: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub username: String,
    pub password: Secret<String>,
    pub database_name: String,
}

impl DatabaseSettings {
    pub fn without_database(&self) -> PgConnectOptions {
        PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .username(&self.username)
            .password(self.password.expose_secret())
            .log_statements(LevelFilter::Debug)
    }

    pub fn with_database(&self) -> PgConnectOptions {
        self.without_database().database(&self.database_name)
    }
}

pub fn get_settings() -> Result<Settings, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    let configuration_directory_path = base_path.join("configuration");

    let environment =
        Environment::try_from(std::env::var("APP_ENVIRONMENT").unwrap_or_else(|_| "local".into()))
            .expect("Failed to parse APP_ENVIRONMENT");

    config::Config::builder()
        .add_source(config::File::from(configuration_directory_path.join("base")).required(true))
        .add_source(
            config::File::from(configuration_directory_path.join(environment.as_str()))
                .required(true),
        )
        .add_source(
            config::Environment::with_prefix("APP")
                .prefix_separator("_")
                .separator("__"),
        )
        .build()?
        .try_deserialize()
}

pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{other} is not a supported environment. Use either `local` or `production`."
            )),
        }
    }
}
