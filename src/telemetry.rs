use tracing::{subscriber::set_global_default, Subscriber};
use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt, EnvFilter, Registry};

pub fn get_subscriber<Writer>(
    env_filter: EnvFilter,
    writer: Writer,
) -> impl Subscriber + Send + Sync
where
    Writer: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let env_filter = EnvFilter::try_from_default_env().unwrap_or(env_filter);

    let formatting_layer = tracing_subscriber::fmt::Layer::default().with_writer(writer);

    Registry::default().with(env_filter).with(formatting_layer)
}

pub fn init_subscriber<T>(subscriber: T)
where
    T: Subscriber + Send + Sync,
{
    set_global_default(subscriber).expect("Failed to set subscriber.");
}
