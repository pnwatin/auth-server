use matoscout_api::{
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};
use once_cell::sync::Lazy;
use tracing_subscriber::EnvFilter;

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

        let application = Application::build()
            .await
            .expect("Failed to build application.");

        tokio::spawn(application.run_until_stopped());

        Self {
            address: "http://127.0.0.1:3000".into(),
        }
    }
}
