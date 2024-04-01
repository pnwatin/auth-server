use auth_server::{
    settings::get_settings,
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let subscriber = get_subscriber(EnvFilter::new("trace"), std::io::stdout);
    init_subscriber(subscriber);

    let settings = get_settings().expect("Failed to get configuration.");

    let application = Application::build(settings).await?;

    application.run_until_stopped().await?;

    Ok(())
}
