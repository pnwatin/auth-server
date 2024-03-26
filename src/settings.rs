use jsonwebtoken::{DecodingKey, EncodingKey};
use once_cell::sync::Lazy;
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
    Test,
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Test => "test",
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
            "test" => Ok(Self::Test),
            other => Err(format!(
                "{other} is not a supported environment. Use either `test`, `local` or `production`."
            )),
        }
    }
}

pub static JWT_CONFIG: Lazy<JWTConfig> =
    Lazy::new(|| JWTConfig::new().expect("Couldn't retreive jwt config."));

pub struct JWTConfig {
    pub access_token_exp_seconds: i64,
    pub refresh_token_exp_seconds: i64,
    pub keys: JWTKeys,
}

pub struct JWTKeys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl JWTConfig {
    fn new() -> Result<JWTConfig, config::ConfigError> {
        let jwt_settings = get_settings()?.jwt;

        let secret = jwt_settings.secret.expose_secret().as_bytes();

        let keys = JWTKeys {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        };

        Ok(Self {
            access_token_exp_seconds: jwt_settings.access_token_exp_seconds,
            refresh_token_exp_seconds: jwt_settings.refresh_token_exp_seconds,
            keys,
        })
    }
}
