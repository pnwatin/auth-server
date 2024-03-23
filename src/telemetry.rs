use tokio::task::{spawn_blocking, JoinHandle};
use tracing::{subscriber::set_global_default, Subscriber};
use tracing_subscriber::{
    fmt::{format::FmtSpan, MakeWriter},
    layer::SubscriberExt,
    EnvFilter, Registry,
};

pub fn get_subscriber<Writer>(
    env_filter: EnvFilter,
    writer: Writer,
) -> impl Subscriber + Send + Sync
where
    Writer: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let env_filter = EnvFilter::try_from_default_env().unwrap_or(env_filter);

    let formatting_layer = tracing_subscriber::fmt::Layer::default()
        .with_writer(writer)
        .with_target(false)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE);

    Registry::default().with(env_filter).with(formatting_layer)
}

pub fn init_subscriber<T>(subscriber: T)
where
    T: Subscriber + Send + Sync,
{
    set_global_default(subscriber).expect("Failed to set subscriber.");
}

pub fn spawn_blocking_with_tracing<F, R>(f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let current_span = tracing::Span::current();

    tokio::task::spawn_blocking(move || current_span.in_scope(f))
}
