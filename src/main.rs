use matoscout_api::{
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let subscriber = get_subscriber(EnvFilter::new("trace"), std::io::stdout);
    init_subscriber(subscriber);

    let application = Application::build().await?;

    application.run_until_stopped().await?;

    Ok(())
}
