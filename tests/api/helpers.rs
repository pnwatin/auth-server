use matoscout_api::{
    settings::get_settings,
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};
use once_cell::sync::Lazy;
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
    pub address: String,
}

impl TestApplication {
    pub async fn spawn() -> Self {
        Lazy::force(&TRACING);

        let settings = {
            let mut settings = get_settings().expect("Failed to get configuration.");

            settings.database.database_name = Uuid::new_v4().to_string();

            settings
        };

        let application = Application::build(settings)
            .await
            .expect("Failed to build application.");

        tokio::spawn(application.run_until_stopped());

        Self {
            address: "http://127.0.0.1:3000".into(),
        }
    }
}
