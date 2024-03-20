use matoscout_api::startup::Application;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let application = Application::build().await?;

    application.run_until_stopped().await?;

    Ok(())
}
